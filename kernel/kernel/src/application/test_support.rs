// Copyright (c) 2026 vivo Mobile Communication Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Small real ELF products for registry/reaper lifecycle tests. Allocation and
//! publication use the same memory service and receipt as application loading.

use super::{
    adapters::{flat_memory::FlatImageMemory, system_paths::SystemLibraryKey},
    publication::{KernelLinkPreparedBatch, KernelLinkPublisher, KernelLinkReceipt},
    registry::{AcquireBatchOutcome, SystemCandidateBacking, SystemDsoLease, SystemDsoRegistry},
};
use alloc::{sync::Arc, vec::Vec};
use blueos_loader::{
    memory::ImageAllocation,
    profile::{ElfClass, ElfMachine, SessionLimits},
    reader::ElfReader,
    CommittedAllocations, ImageDependency, ImageHandle, LoadRequest, LoadResult, LoadedImage,
    LoaderBackend, Publication,
};
use core::sync::atomic::{AtomicUsize, Ordering};

/// Full loader calls need the same explicit stack budget as loader_unittest.
/// The kernel harness itself runs on a smaller static system-thread stack.
pub(super) fn with_loader_stack(test: impl FnOnce() + Send + 'static) {
    let done = Arc::new(AtomicUsize::new(0));
    let worker_done = done.clone();
    crate::thread::spawn_with_stack(64 * 1024, move || {
        test();
        worker_done.store(1, Ordering::Release);
        let _ = crate::sync::atomic_wake(&worker_done, usize::MAX);
    })
    .expect("lifecycle test worker");
    while done.load(Ordering::Acquire) == 0 {
        let _ = crate::sync::atomic_wait(&done, 0, crate::time::Tick::MAX);
    }
}

pub(super) struct Reader(Vec<u8>);
impl ElfReader for Reader {
    fn len(&self) -> LoadResult<u64> {
        Ok(self.0.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> LoadResult<()> {
        dst.copy_from_slice(&self.0[offset as usize..offset as usize + dst.len()]);
        Ok(())
    }
}

struct Backend {
    memory: FlatImageMemory,
    publisher: KernelLinkPublisher,
    shared: bool,
}
impl LoaderBackend for Backend {
    type Source = &'static [u8];
    type Reader = Reader;
    type Memory = FlatImageMemory;
    type PreparedPublication = KernelLinkPreparedBatch;
    type Receipt = KernelLinkReceipt;
    fn identity<'a>(&self, source: &'a Self::Source) -> &'a [u8] {
        source
    }
    fn is_shared(&self, _: &Self::Source) -> bool {
        self.shared
    }
    fn open(&mut self, _: &Self::Source) -> LoadResult<Reader> {
        Ok(Reader(elf(self.shared)))
    }
    fn snapshot(&mut self, _: &Self::Source) -> LoadResult<Option<ImageHandle>> {
        Ok(None)
    }
    fn resolve(&mut self, _: &Self::Source, _: &[u8]) -> LoadResult<Self::Source> {
        panic!("the test image has no DT_NEEDED")
    }
    fn resolve_snapshot(&mut self, _: &ImageDependency) -> LoadResult<Self::Source> {
        panic!("the test image has no DT_NEEDED")
    }
    fn acquire(&mut self, _: &[Self::Source], _: &[ImageHandle]) -> LoadResult<Vec<ImageHandle>> {
        Ok(Vec::new())
    }
    fn memory(&mut self) -> FlatImageMemory {
        self.memory.clone()
    }
    fn prepare_publication(
        &mut self,
        publication: &Publication,
    ) -> LoadResult<KernelLinkPreparedBatch> {
        self.publisher.prepare(publication)
    }
    unsafe fn commit_publication(
        &mut self,
        prepared: KernelLinkPreparedBatch,
        allocations: CommittedAllocations,
    ) -> KernelLinkReceipt {
        self.publisher.commit(prepared, allocations)
    }
    fn complete_load(&mut self, _: &mut LoadedImage<KernelLinkReceipt>) -> LoadResult<()> {
        Ok(())
    }
    fn abort_publication(&mut self, receipt: KernelLinkReceipt) {
        drop(receipt);
    }
    fn cancel_load(&mut self) {
        self.publisher.cancel();
    }
}

pub(super) fn load_image(
    memory: &FlatImageMemory,
    path: &'static [u8],
    shared: bool,
) -> LoadedImage<KernelLinkReceipt> {
    let mut backend = Backend {
        memory: memory.clone(),
        publisher: KernelLinkPublisher::new(memory.clone()),
        shared,
    };
    let request = if shared {
        LoadRequest::shared_object(path, super::board_dynamic_profile(), SessionLimits::DEFAULT)
    } else {
        LoadRequest::executable(path, super::board_dynamic_profile(), SessionLimits::DEFAULT)
    };
    blueos_loader::load(request, &mut backend).expect("test ELF loads")
}

pub(super) fn publish_candidates(
    registry: &SystemDsoRegistry,
    memory: &FlatImageMemory,
    paths: &[&'static [u8]],
    component: &[&'static [u8]],
    fini: &[Vec<usize>],
    dependencies: &[Vec<SystemLibraryKey>],
) -> (Vec<SystemDsoLease>, Vec<ImageAllocation>) {
    let keys: Vec<_> = paths
        .iter()
        .map(|path| SystemLibraryKey::from_bytes(path).unwrap())
        .collect();
    let AcquireBatchOutcome::Acquired(mut batch) = registry.acquire_batch(&keys) else {
        panic!("test candidates are vacant")
    };
    let mut permits = Vec::new();
    let mut backings = Vec::new();
    let mut allocations = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        let mut image = load_image(memory, path, true);
        let (mut images, mut leases) = image.receipt_mut().take_system_backings();
        let allocation = leases.pop().unwrap();
        allocations.push(*allocation.allocation());
        let permit_index = batch
            .loads
            .iter()
            .position(|(key, _)| key == &keys[index])
            .unwrap();
        permits.push(
            registry
                .publish_relocated(batch.loads.swap_remove(permit_index).1)
                .unwrap(),
        );
        backings.push(SystemCandidateBacking {
            descriptor: images.pop().unwrap(),
            allocation,
            fini_plan: fini[index].clone(),
            dependency_keys: dependencies[index].clone(),
            dependencies: Vec::with_capacity(dependencies[index].len()),
            scc_members: if component.is_empty() {
                alloc::vec![keys[index].clone()]
            } else {
                component
                    .iter()
                    .map(|path| SystemLibraryKey::from_bytes(path).unwrap())
                    .collect()
            },
            keep_cached: false,
        });
    }
    let init = registry
        .publish_relocated_batch(permits, &mut backings)
        .unwrap();
    (
        registry.finish_initialization_batch(init).unwrap(),
        allocations,
    )
}

fn elf(shared: bool) -> Vec<u8> {
    let profile = super::board_dynamic_profile();
    let mut bytes = alloc::vec![0; 256];
    bytes[..7].copy_from_slice(&[
        0x7f,
        b'E',
        b'L',
        b'F',
        u64::from(profile.class()) as u8,
        1,
        1,
    ]);
    put16(&mut bytes, 16, 3); // ET_DYN
    put16(&mut bytes, 18, u64::from(profile.machine()) as u16);
    put32(&mut bytes, 20, 1);
    let entry = if shared {
        0
    } else {
        0x10e0 | u64::from(profile.entry_mode().is_thumb())
    };
    let flags = if profile.machine() == ElfMachine::Arm {
        if profile.header_flags().accepts(0x0500_0400) {
            0x0500_0400
        } else {
            0x0500_0200
        }
    } else {
        0
    };
    if profile.class() == ElfClass::Elf32 {
        put32(&mut bytes, 24, entry as u32);
        put32(&mut bytes, 28, 52);
        put32(&mut bytes, 36, flags);
        put16(&mut bytes, 40, 52);
        put16(&mut bytes, 42, 32);
        put16(&mut bytes, 44, 2);
        for (at, value) in [
            (52, 1),
            (60, 0x1000),
            (68, 256),
            (72, 256),
            (76, 5),
            (80, 4),
            (84, 2),
            (88, 116),
            (92, 0x1074),
            (100, 8),
            (104, 8),
            (108, 4),
            (112, 4),
        ] {
            put32(&mut bytes, at, value);
        }
    } else {
        put64(&mut bytes, 24, entry);
        put64(&mut bytes, 32, 64);
        put32(&mut bytes, 48, flags);
        put16(&mut bytes, 52, 64);
        put16(&mut bytes, 54, 56);
        put16(&mut bytes, 56, 2);
        for (at, value) in [(64, 1), (68, 5), (120, 2), (124, 4)] {
            put32(&mut bytes, at, value);
        }
        for (at, value) in [
            (80, 0x1000),
            (96, 256),
            (104, 256),
            (112, 4),
            (128, 176),
            (136, 0x10b0),
            (152, 16),
            (160, 16),
            (168, 4),
        ] {
            put64(&mut bytes, at, value);
        }
    }
    bytes
}

/// Native code tail-calls a kernel test callback, preserving the entry ABI.
/// These ELF fixtures go through VFS, parsing, mapping and lifecycle planning;
/// callback bodies can observe state after the real mapped code was entered.
pub(super) fn lifecycle_elf(
    shared: bool,
    needed: &[&[u8]],
    init: Option<usize>,
    fini: Option<usize>,
    entry: Option<usize>,
) -> Vec<u8> {
    let profile = super::board_dynamic_profile();
    let mut bytes = elf(shared);
    bytes.resize(1024, 0);
    let thumb = usize::from(profile.entry_mode().is_thumb());
    let mut tags = Vec::new();
    if !needed.is_empty() {
        let mut names = alloc::vec![0];
        for name in needed {
            tags.push((1, names.len() as u64)); // DT_NEEDED
            names.extend_from_slice(name);
            names.push(0);
        }
        assert!(384 + names.len() <= 448, "fixture dependency names");
        bytes[384..384 + names.len()].copy_from_slice(&names);
        tags.push((5, 0x1180)); // DT_STRTAB
        tags.push((10, names.len() as u64)); // DT_STRSZ
        tags.push((6, 0x1200)); // DT_SYMTAB: the mandatory null symbol
        tags.push((
            11,
            if profile.class() == ElfClass::Elf32 {
                16
            } else {
                24
            },
        ));
        tags.push((4, 0x1240)); // DT_HASH: one bucket and one null-symbol chain
        put32(&mut bytes, 576, 1);
        put32(&mut bytes, 580, 1);
    }
    for (tag, at, target) in [(12, 320, init), (13, 352, fini)] {
        if let Some(target) = target {
            write_callback(&mut bytes[at..at + 32], target);
            tags.push((tag, (0x1000 + at + thumb) as u64));
        }
    }
    tags.push((0, 0));
    if !shared {
        let entry = entry.expect("an executable fixture needs its entry callback");
        write_callback(&mut bytes[448..480], entry);
    }
    if profile.class() == ElfClass::Elf32 {
        if !shared {
            put32(&mut bytes, 24, (0x11c0 + thumb) as u32);
        }
        put32(&mut bytes, 68, 1024);
        put32(&mut bytes, 72, 1024);
        put32(&mut bytes, 100, (tags.len() * 8) as u32);
        put32(&mut bytes, 104, (tags.len() * 8) as u32);
        assert!(116 + tags.len() * 8 <= 320);
        for (index, (tag, value)) in tags.into_iter().enumerate() {
            put32(&mut bytes, 116 + index * 8, tag as u32);
            put32(&mut bytes, 120 + index * 8, value as u32);
        }
    } else {
        if !shared {
            put64(&mut bytes, 24, (0x11c0 + thumb) as u64);
        }
        put64(&mut bytes, 96, 1024);
        put64(&mut bytes, 104, 1024);
        put64(&mut bytes, 152, (tags.len() * 16) as u64);
        put64(&mut bytes, 160, (tags.len() * 16) as u64);
        assert!(176 + tags.len() * 16 <= 320);
        for (index, (tag, value)) in tags.into_iter().enumerate() {
            put64(&mut bytes, 176 + index * 16, tag);
            put64(&mut bytes, 184 + index * 16, value);
        }
    }
    bytes
}

fn write_callback(bytes: &mut [u8], callback: usize) {
    match super::board_dynamic_profile().machine() {
        ElfMachine::Arm => {
            put16(bytes, 0, 0x4b00); // ldr r3, [pc, #0]
            put16(bytes, 2, 0x4718); // bx r3
            put32(bytes, 4, callback as u32);
        }
        ElfMachine::Riscv => {
            put32(bytes, 0, 0x0000_0297); // auipc t0, 0
            put32(bytes, 8, 0x0002_8067); // jr t0
            if super::board_dynamic_profile().class() == ElfClass::Elf32 {
                put32(bytes, 4, 0x00c2_a283); // lw t0, 12(t0)
                put32(bytes, 12, callback as u32);
            } else {
                put32(bytes, 4, 0x0102_b283); // ld t0, 16(t0)
                put64(bytes, 16, callback as u64);
            }
        }
        ElfMachine::Aarch64 => {
            put32(bytes, 0, 0x5800_0050); // ldr x16, .+8
            put32(bytes, 4, 0xd61f_0200); // br x16
            put64(bytes, 8, callback as u64);
        }
        _ => unreachable!("native loader fixture architecture"),
    }
}

pub(super) fn install_elf(path: &str, bytes: &[u8]) {
    for (index, _) in path.match_indices('/').skip(1) {
        let mut directory = path.as_bytes()[..index].to_vec();
        directory.push(0);
        let rc = unsafe { crate::vfs::syscalls::mkdir(directory.as_ptr().cast(), 0o755) };
        assert!(rc == 0 || rc == -libc::EEXIST);
    }
    let mut name = path.as_bytes().to_vec();
    name.push(0);
    let fd = crate::vfs::syscalls::open(
        name.as_ptr().cast(),
        libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
        0o644,
    );
    assert!(fd >= 0, "install {path}");
    assert_eq!(
        crate::vfs::syscalls::write(fd, bytes.as_ptr(), bytes.len()),
        bytes.len() as isize
    );
    assert_eq!(crate::vfs::syscalls::close(fd), 0);
}

pub(super) fn remove_elf(path: &str) {
    let mut name = path.as_bytes().to_vec();
    name.push(0);
    assert_eq!(crate::vfs::syscalls::unlink(name.as_ptr().cast()), 0);
}

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
