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

use crate::{
    error::{ErrorContext, LoadErrorKind},
    load,
    memory::{
        AllocationLease, AllocationOffset, AllocationRequest, ImageAllocation, ImageMemory,
        ImageProtectionMemory, MemoryMapper, MemoryPermissions, MutationProgress,
        PreparedProtectionPlan, ProtectionCapabilities, ProtectionLevel,
    },
    planning::LoadPlan,
    profile::{LoadLimits, LoadProfile, SessionLimits},
    reader::ElfReader,
    tests::fixture::SliceElfReader,
    CommittedAllocations, ImageHandle, LoadError, LoadRequest, LoadResult, LoadedImage,
    LoaderBackend, Publication,
};
use alloc::{rc::Rc, vec::Vec};
use blueos_test_macro::test;
use core::cell::{Cell, RefCell};

#[derive(Clone)]
struct SharedMemory {
    mapper: Rc<RefCell<MemoryMapper>>,
    acquired: Rc<Cell<bool>>,
    allocations: Rc<Cell<usize>>,
    releases: Rc<Cell<usize>>,
}
impl ImageMemory for SharedMemory {
    fn allocate_image(&mut self, request: AllocationRequest) -> LoadResult<AllocationLease> {
        assert!(self.acquired.get(), "reserve closure before mapping");
        self.allocations.set(self.allocations.get() + 1);
        self.mapper.borrow_mut().allocate_image(request)
    }
    fn abort_image(&mut self, lease: AllocationLease, progress: MutationProgress) {
        self.mapper.borrow_mut().abort_image(lease, progress);
    }
    fn release_committed(&mut self, lease: AllocationLease) {
        self.releases.set(self.releases.get() + 1);
        self.mapper.borrow_mut().release_committed(lease);
    }
    fn image_span(
        &self,
        allocation: &ImageAllocation,
        offset: AllocationOffset,
        len: u64,
    ) -> LoadResult<*mut u8> {
        self.mapper.borrow().image_span(allocation, offset, len)
    }
    fn read(
        &self,
        allocation: &ImageAllocation,
        offset: AllocationOffset,
        dst: &mut [u8],
    ) -> LoadResult<()> {
        self.mapper.borrow().read(allocation, offset, dst)
    }
    fn write(
        &mut self,
        allocation: &ImageAllocation,
        offset: AllocationOffset,
        bytes: &[u8],
    ) -> LoadResult<()> {
        self.mapper.borrow_mut().write(allocation, offset, bytes)
    }
    fn zero(
        &mut self,
        allocation: &ImageAllocation,
        offset: AllocationOffset,
        len: u64,
    ) -> LoadResult<()> {
        self.mapper.borrow_mut().zero(allocation, offset, len)
    }
}
impl ImageProtectionMemory for SharedMemory {
    fn protect(
        &mut self,
        allocation: &ImageAllocation,
        offset: AllocationOffset,
        len: u64,
        permissions: MemoryPermissions,
    ) -> LoadResult<ProtectionLevel> {
        self.mapper
            .borrow_mut()
            .protect(allocation, offset, len, permissions)
    }
    fn protection_capabilities(&self) -> ProtectionCapabilities {
        self.mapper.borrow().protection_capabilities()
    }
    fn validate_protection_aliases(
        &self,
        allocation: &ImageAllocation,
        plan: &PreparedProtectionPlan,
    ) -> LoadResult<()> {
        self.mapper
            .borrow()
            .validate_protection_aliases(allocation, plan)
    }
}
struct Reader(Rc<[u8]>);
impl ElfReader for Reader {
    fn len(&self) -> LoadResult<u64> {
        Ok(self.0.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> LoadResult<()> {
        SliceElfReader::new(&self.0).read_exact_at(offset, dst)
    }
}
struct Receipt {
    memory: SharedMemory,
    leases: Vec<AllocationLease>,
}
impl Drop for Receipt {
    fn drop(&mut self) {
        for lease in self.leases.drain(..) {
            self.memory.release_committed(lease);
        }
    }
}
struct Backend {
    files: Vec<(&'static str, Rc<[u8]>)>,
    memory: SharedMemory,
    reject_acquire: bool,
    reject_publish: bool,
    reject_complete: bool,
    shared: bool,
    commits: usize,
    aborts: usize,
    cancels: usize,
}
impl Backend {
    fn new(files: Vec<(&'static str, Vec<u8>)>) -> Self {
        Self {
            files: files
                .into_iter()
                .map(|(name, bytes)| (name, Rc::from(bytes)))
                .collect(),
            memory: SharedMemory {
                mapper: Rc::new(RefCell::new(MemoryMapper::new(None))),
                acquired: Rc::new(Cell::new(false)),
                allocations: Rc::new(Cell::new(0)),
                releases: Rc::new(Cell::new(0)),
            },
            reject_acquire: false,
            reject_publish: false,
            reject_complete: false,
            shared: false,
            commits: 0,
            aborts: 0,
            cancels: 0,
        }
    }
}
fn failure() -> LoadError {
    LoadError::new(LoadErrorKind::Backend, ErrorContext::None)
}
impl LoaderBackend for Backend {
    type Source = &'static str;
    type Reader = Reader;
    type Memory = SharedMemory;
    type PreparedPublication = Vec<AllocationLease>;
    type Receipt = Receipt;
    fn identity<'a>(&self, source: &'a Self::Source) -> &'a [u8] {
        source.as_bytes()
    }
    fn is_shared(&self, _: &Self::Source) -> bool {
        self.shared
    }
    fn open(&mut self, source: &Self::Source) -> LoadResult<Reader> {
        self.files
            .iter()
            .find(|(name, _)| name == source)
            .map(|(_, bytes)| Reader(bytes.clone()))
            .ok_or_else(failure)
    }
    fn resolve(&mut self, _: &Self::Source, name: &[u8]) -> LoadResult<Self::Source> {
        self.files
            .iter()
            .find(|(source, _)| source.as_bytes() == name)
            .map(|(source, _)| *source)
            .ok_or_else(failure)
    }
    fn acquire(
        &mut self,
        sources: &[Self::Source],
        _: &[ImageHandle],
    ) -> LoadResult<Vec<ImageHandle>> {
        assert_eq!(sources.len(), self.files.len());
        if self.reject_acquire {
            return Err(failure());
        }
        self.memory.acquired.set(true);
        Ok(Vec::new())
    }
    fn memory(&mut self) -> SharedMemory {
        self.memory.clone()
    }
    fn prepare_publication(
        &mut self,
        publication: &Publication,
    ) -> LoadResult<Vec<AllocationLease>> {
        if self.reject_publish {
            return Err(failure());
        }
        assert_eq!(publication.shared_images(), usize::from(self.shared));
        let mut leases = Vec::new();
        leases
            .try_reserve_exact(publication.private_images() + publication.shared_images())
            .map_err(|_| failure())?;
        Ok(leases)
    }
    unsafe fn commit_publication(
        &mut self,
        mut leases: Vec<AllocationLease>,
        allocations: CommittedAllocations,
    ) -> Receipt {
        self.commits += 1;
        for (_, lease) in allocations.into_images() {
            leases.push(lease);
        }
        Receipt {
            memory: self.memory.clone(),
            leases,
        }
    }
    fn complete_load(&mut self, image: &mut LoadedImage<Receipt>) -> LoadResult<()> {
        assert_eq!(image.images().count(), self.files.len());
        if self.reject_complete {
            Err(failure())
        } else {
            Ok(())
        }
    }
    fn abort_publication(&mut self, receipt: Receipt) {
        self.aborts += 1;
        drop(receipt);
    }
    fn cancel_load(&mut self) {
        self.cancels += 1;
    }
}

#[test]
fn load_complete_entry_transfers_one_allocation() {
    let (bytes, profile) = super::linker::native_fixture();
    let mut backend = Backend::new(alloc::vec![("root", bytes)]);
    let loaded = load(
        LoadRequest::new("root", profile, SessionLimits::DEFAULT),
        &mut backend,
    )
    .expect("complete load");
    let root = loaded.images().next().unwrap();
    assert_eq!(root.identity(), b"root");
    assert!(loaded.is_new(root));
    assert_eq!(loaded.lookup_scope(root).len(), 1);
    assert!(loaded.entry().unwrap().get() != 0);
    let (phdr, phent, phnum) = loaded.program_headers();
    assert_eq!(phnum, 1, "static images retain program-header geometry");
    assert_eq!(
        phent,
        match profile.class() {
            crate::profile::ElfClass::Elf32 => 32,
            crate::profile::ElfClass::Elf64 => 56,
        }
    );
    assert!(phdr.is_some());
    assert!(loaded.retained_images().is_empty());
    assert_eq!(backend.commits, 1);
    drop(loaded.into_receipt());
    assert_eq!(backend.memory.releases.get(), 1);
}

fn set_entry(bytes: &mut [u8], entry: u64) {
    if bytes[4] == 1 {
        bytes[24..28].copy_from_slice(&(entry as u32).to_le_bytes());
    } else {
        bytes[24..32].copy_from_slice(&entry.to_le_bytes());
    }
}

#[test]
fn load_registry_root_with_entry_remains_shared() {
    let (_, profile) = super::linker::native_fixture();
    let mut backend = Backend::new(alloc::vec![("root", native_dso(&[]))]);
    backend.shared = true;
    let loaded = load(
        LoadRequest::new("root", profile, SessionLimits::DEFAULT),
        &mut backend,
    )
    .expect("a SONAME-less DSO may have a nonzero entry");
    assert!(loaded.images().next().unwrap().is_shared());
    assert!(loaded.entry().is_none());
    assert_eq!(backend.commits, 1);
    drop(loaded);
    assert_eq!(backend.memory.releases.get(), 1);
}

#[test]
fn load_registry_rejects_executable_roots_before_acquire() {
    let (_, profile) = super::linker::native_fixture();
    let pie = native_dso_with_flags(&[], goblin::elf::dynamic::DF_1_PIE);
    let mut exec = native_dso(&[]);
    exec[16..18].copy_from_slice(&goblin::elf::header::ET_EXEC.to_le_bytes());
    for bytes in [pie, exec] {
        let mut backend = Backend::new(alloc::vec![("root", bytes)]);
        backend.shared = true;
        let error = load(
            LoadRequest::new("root", profile, SessionLimits::DEFAULT),
            &mut backend,
        )
        .err()
        .expect("executables cannot enter the shared-image registry");
        assert!(matches!(error.kind(), LoadErrorKind::UnsupportedByProfile));
        assert!(!backend.memory.acquired.get());
        assert_eq!(backend.memory.allocations.get(), 0);
        assert_eq!(backend.cancels, 1);
    }
}

#[test]
fn load_detects_shared_root_without_an_entry() {
    let (_, profile) = super::linker::native_fixture();
    let mut bytes = native_dso(&[]);
    set_entry(&mut bytes, 0);
    let mut backend = Backend::new(alloc::vec![("root", bytes)]);
    let loaded = load(
        LoadRequest::new("root", profile, SessionLimits::DEFAULT),
        &mut backend,
    )
    .expect("shared root is inferred from ELF");
    assert!(loaded.entry().is_none());
    assert!(loaded.startup().is_empty());
    assert_eq!(backend.memory.allocations.get(), 1);
    drop(loaded.into_receipt());
    assert_eq!(backend.memory.releases.get(), 1);
}

#[test]
fn load_marked_pie_requires_an_executable_entry() {
    let (_, profile) = super::linker::native_fixture();
    let mut bytes = native_dso_with_flags(&[], goblin::elf::dynamic::DF_1_PIE);
    set_entry(&mut bytes, 0);
    let mut backend = Backend::new(alloc::vec![("root", bytes)]);
    assert!(load(
        LoadRequest::new("root", profile, SessionLimits::DEFAULT),
        &mut backend
    )
    .is_err());
    assert_eq!(backend.commits, 0);
}

#[test]
fn load_detects_fixed_exec_without_a_selected_mode() {
    use crate::memory::{AllocationOwnership, MemoryRegion};
    use blueos_infra::storage::Storage;
    let backing = Storage::try_from_layout(core::alloc::Layout::from_size_align(0x100, 4).unwrap())
        .expect("fixed test backing");
    let base = backing.base() as usize;
    let (mut bytes, profile) = super::linker::native_fixture();
    bytes[16..18].copy_from_slice(&goblin::elf::header::ET_EXEC.to_le_bytes());
    if bytes[4] == 1 {
        bytes[60..64].copy_from_slice(&(base as u32).to_le_bytes());
        bytes[64..68].copy_from_slice(&(base as u32).to_le_bytes());
    } else {
        bytes[80..88].copy_from_slice(&(base as u64).to_le_bytes());
        bytes[88..96].copy_from_slice(&(base as u64).to_le_bytes());
    }
    set_entry(
        &mut bytes,
        base as u64 | u64::from(profile.entry_mode().is_thumb()),
    );
    let regions = alloc::boxed::Box::leak(alloc::boxed::Box::new([unsafe {
        // The test owns this backing until its receipt and backend are gone.
        MemoryRegion::new(
            base,
            base + 0x100,
            MemoryPermissions::READ
                .bitor(MemoryPermissions::WRITE)
                .bitor(MemoryPermissions::EXECUTE),
        )
    }]));
    let mut backend = Backend::new(alloc::vec![("root", bytes)]);
    backend.memory.mapper = Rc::new(RefCell::new(MemoryMapper::new(Some(regions))));
    let mut loaded = load(
        LoadRequest::new("root", profile, SessionLimits::DEFAULT),
        &mut backend,
    )
    .expect("ET_EXEC uses the same public load entry");
    assert_eq!(
        loaded.entry().unwrap().get(),
        base as u64 | u64::from(profile.entry_mode().is_thumb())
    );
    assert_eq!(
        loaded.receipt_mut().leases[0].allocation().ownership(),
        AllocationOwnership::BorrowedFixed
    );
    drop(loaded.into_receipt());
    assert_eq!(backend.memory.releases.get(), 1);
    drop(backend);
    drop(backing);
}

#[test]
fn load_fixed_exec_rejects_unreserved_addresses() {
    let (mut bytes, profile) = super::linker::native_fixture();
    bytes[16..18].copy_from_slice(&goblin::elf::header::ET_EXEC.to_le_bytes());
    let mut backend = Backend::new(alloc::vec![("root", bytes)]);
    let error = load(
        LoadRequest::new("root", profile, SessionLimits::DEFAULT),
        &mut backend,
    )
    .err()
    .expect("fixed placement requires platform permission");
    assert!(matches!(error.kind(), LoadErrorKind::OutOfBounds));
    assert_eq!(backend.commits, 0);
}

#[test]
fn load_rejects_executable_dependencies_before_mapping() {
    let mut dependency = dso_elf(&[], None);
    dependency[16..18].copy_from_slice(&goblin::elf::header::ET_EXEC.to_le_bytes());
    let mut backend = Backend::new(alloc::vec![
        ("root", dso_elf(&["left"], None)),
        ("left", dependency),
    ]);
    let error = load(plan_request(SessionLimits::DEFAULT), &mut backend)
        .err()
        .expect("a dependency must be a shared object");
    assert!(matches!(error.kind(), LoadErrorKind::UnsupportedByProfile));
    assert!(!backend.memory.acquired.get());
    assert_eq!(backend.memory.allocations.get(), 0);
}
#[test]
fn load_completion_failure_releases_committed_receipt_once() {
    let (bytes, profile) = super::linker::native_fixture();
    let mut backend = Backend::new(alloc::vec![("root", bytes)]);
    backend.reject_complete = true;
    assert!(load(
        LoadRequest::new("root", profile, SessionLimits::DEFAULT),
        &mut backend
    )
    .is_err());
    assert_eq!(
        (backend.commits, backend.aborts, backend.cancels),
        (1, 1, 1)
    );
    assert_eq!(backend.memory.releases.get(), 1);
}
#[test]
fn load_publication_failure_aborts_before_commit() {
    let (bytes, profile) = super::linker::native_fixture();
    let mut backend = Backend::new(alloc::vec![("root", bytes)]);
    backend.reject_publish = true;
    assert!(load(
        LoadRequest::new("root", profile, SessionLimits::DEFAULT),
        &mut backend
    )
    .is_err());
    assert_eq!(
        (backend.commits, backend.aborts, backend.cancels),
        (0, 0, 1)
    );
    backend.reject_publish = false;
    let loaded = load(
        LoadRequest::new("root", profile, SessionLimits::DEFAULT),
        &mut backend,
    )
    .expect("rollback freed mapper");
    drop(loaded.into_receipt());
}
#[test]
fn load_acquire_failure_maps_no_images() {
    let (bytes, profile) = super::linker::native_fixture();
    let mut backend = Backend::new(alloc::vec![("root", bytes)]);
    backend.reject_acquire = true;
    assert!(load(
        LoadRequest::new("root", profile, SessionLimits::DEFAULT),
        &mut backend
    )
    .is_err());
    assert_eq!(backend.memory.allocations.get(), 0);
    assert_eq!(backend.cancels, 1);
}

// Reusing a provider must preserve dependencies beneath it without mapping
// either provider again, and expose that closure to dlsym and retention.
#[test]
fn load_reused_provider_preserves_transitive_closure() {
    let (_, profile) = super::linker::native_fixture();
    let c_bytes = native_dso(&[]);
    let b_bytes = native_dso(&["C"]);
    let root_bytes = native_dso(&["B"]);
    let mut c_backend = Backend::new(alloc::vec![("C", c_bytes.clone())]);
    let c = load(
        LoadRequest::new("C", profile, SessionLimits::DEFAULT),
        &mut c_backend,
    )
    .expect("load C");
    let c_handle = c.images().next().unwrap().clone();
    let mut b_backend = Backend::new(alloc::vec![("B", b_bytes.clone()), ("C", c_bytes.clone())]);
    let b_request = LoadRequest::new("B", profile, SessionLimits::DEFAULT)
        .with_namespace(alloc::vec![c_handle.clone()], Vec::new());
    let b = load(b_request, &mut b_backend).expect("load B with existing C");
    let b_handle = b.images().next().unwrap().clone();
    let mut backend = Backend::new(alloc::vec![
        ("root", root_bytes),
        ("B", b_bytes),
        ("C", c_bytes)
    ]);
    let request = LoadRequest::new("root", profile, SessionLimits::DEFAULT)
        .with_namespace(alloc::vec![b_handle, c_handle], Vec::new());
    let loaded = load(request, &mut backend).expect("reuse B and its C dependency");
    let root = loaded.images().next().unwrap();
    assert_eq!(
        loaded
            .lookup_scope(root)
            .iter()
            .map(|image| image.identity())
            .collect::<Vec<_>>(),
        [b"root".as_slice(), b"B".as_slice(), b"C".as_slice()]
    );
    assert_eq!(loaded.retained_images().len(), 2);
    assert_eq!(backend.memory.allocations.get(), 1);
    drop(loaded.into_receipt());
    drop(b.into_receipt());
    drop(c.into_receipt());
}

fn native_dso(needed: &[&str]) -> Vec<u8> {
    native_dso_with_flags(needed, 0)
}

fn native_dso_with_flags(needed: &[&str], dynamic_flags: u64) -> Vec<u8> {
    use super::fixture::ElfFixtureBuilder;
    use goblin::elf::{
        dynamic::{DT_FLAGS_1, DT_HASH, DT_NEEDED, DT_STRSZ, DT_STRTAB, DT_SYMENT, DT_SYMTAB},
        header::*,
    };
    #[cfg(target_arch = "arm")]
    let (builder, flags, entry, header, phdr) = (
        ElfFixtureBuilder::elf32(EM_ARM, ET_DYN),
        0x0500_0200,
        0x1001,
        52,
        32,
    );
    #[cfg(target_arch = "riscv32")]
    let (builder, flags, entry, header, phdr) = (
        ElfFixtureBuilder::elf32(EM_RISCV, ET_DYN),
        0,
        0x1000,
        52,
        32,
    );
    #[cfg(target_arch = "riscv64")]
    let (builder, flags, entry, header, phdr) = (
        ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN),
        0,
        0x1000,
        64,
        56,
    );
    #[cfg(target_arch = "aarch64")]
    let (builder, flags, entry, header, phdr) = (
        ElfFixtureBuilder::elf64(EM_AARCH64, ET_DYN),
        0,
        0x1000,
        64,
        56,
    );
    let mut names = alloc::vec![0];
    let mut entries = Vec::new();
    for name in needed {
        entries.push((DT_NEEDED as u32, names.len() as u64));
        names.extend_from_slice(name.as_bytes());
        names.push(0);
    }
    entries.push((DT_FLAGS_1 as u32, dynamic_flags));
    entries.push((DT_SYMTAB as u32, 0x1200));
    entries.push((DT_SYMENT as u32, if header == 52 { 16 } else { 24 }));
    entries.push((DT_HASH as u32, 0x1240));
    entries.push((DT_STRTAB as u32, 0x1300));
    entries.push((DT_STRSZ as u32, names.len() as u64));
    let mut bytes = builder
        .with_flags(flags)
        .with_load_segment(0x1000, 0x400, 0x400, 4)
        .with_entry(entry)
        .with_dynamic_entries(0x1000 + 2 * phdr, &entries)
        .with_dynstr(header + 0x300, &names)
        .build();
    for (index, word) in [1u32, 1, 0, 0].into_iter().enumerate() {
        let at = header + 0x240 + index * 4;
        bytes[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn plan_request(limits: SessionLimits) -> LoadRequest<&'static str> {
    LoadRequest::new("root", LoadProfile::arm_thumb_soft_float(), limits)
}
#[test]
fn planning_closes_diamond_and_cycle_in_bfs_order() {
    let mut backend = Backend::new(alloc::vec![
        ("root", dso_elf(&["left", "right", "left"], None)),
        ("left", dso_elf(&["leaf"], None)),
        ("right", dso_elf(&["leaf"], None)),
        ("leaf", dso_elf(&["left"], None)),
    ]);
    let plan =
        LoadPlan::build(&plan_request(SessionLimits::DEFAULT), &mut backend).expect("closed plan");
    assert_eq!(
        plan.images
            .iter()
            .map(|image| image.source)
            .collect::<Vec<_>>(),
        ["root", "left", "right", "leaf"]
    );
    assert_eq!(plan.edges.len(), 6);
    assert_eq!(plan.edges[0].provider, plan.edges[2].provider);
    assert_eq!(plan.edges[3].provider, plan.edges[4].provider);
    assert_eq!(backend.memory.allocations.get(), 0);
}
#[test]
fn planning_enforces_image_and_depth_limits_before_mapping() {
    let mut backend = Backend::new(alloc::vec![
        ("root", dso_elf(&["left"], None)),
        ("left", dso_elf(&["leaf"], None)),
        ("leaf", dso_elf(&[], None))
    ]);
    for (images, depth) in [(2, 32), (64, 2)] {
        let limits = SessionLimits::new(
            LoadLimits::DEFAULT,
            images,
            1024,
            depth,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            256,
            256,
        );
        let error = LoadPlan::build(&plan_request(limits), &mut backend)
            .err()
            .expect("bounded plan");
        assert!(matches!(error.kind(), LoadErrorKind::ResourceLimit));
    }
    assert_eq!(backend.memory.allocations.get(), 0);
}
#[test]
fn load_request_discovers_dependencies_without_a_selected_mode() {
    let mut backend = Backend::new(alloc::vec![
        ("root", dso_elf(&["left"], None)),
        ("left", dso_elf(&[], None)),
    ]);
    let plan = LoadPlan::build(&plan_request(SessionLimits::DEFAULT), &mut backend)
        .expect("dependencies are inferred from DT_NEEDED");
    assert_eq!(plan.images.len(), 2);
    assert_eq!(plan.edges.len(), 1);
    assert!(!backend.memory.acquired.get());
}

fn dso_elf(needed: &[&str], soname: Option<&str>) -> Vec<u8> {
    // dynstr: NUL-joined names, prefixed by a 1-byte padding NUL so
    // every name offset is >= 1 (offset 0 would be an empty name).
    let mut dynstr: Vec<u8> = alloc::vec![0];
    let mut offsets = Vec::new();
    for name in needed.iter().chain(soname.iter()) {
        offsets.push(dynstr.len());
        dynstr.extend_from_slice(name.as_bytes());
        dynstr.push(0);
    }
    // The dynstr's vaddr: the PT_LOAD maps file offset `str_off` at
    // vaddr 0x1000 + str_off. Two name-position entries always come
    // first, so dyn_len (and thus str_off) is computable up front.
    let dyn_len = (2 + needed.len() + usize::from(soname.is_some()) + 1) * 8;
    let str_off = DYN_OFF + dyn_len;
    let strsz = dynstr.len();
    let mut entries: Vec<(u32, u64)> = alloc::vec![
        (DT_STRTAB, 0x1000 + str_off as u64),
        (DT_STRSZ, strsz as u64),
    ];
    for &offset in &offsets[..needed.len()] {
        entries.push((DT_NEEDED, offset as u64));
    }
    if soname.is_some() {
        entries.push((DT_SONAME, offsets[needed.len()] as u64));
    }

    let mut bytes = alloc::vec![0u8; str_off + strsz];
    // ehdr
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 1; // ELFCLASS32
    bytes[5] = 1; // ELFDATA2LSB
    bytes[6] = 1; // EV_CURRENT
    bytes[16..18].copy_from_slice(&(ET_DYN as u16).to_le_bytes()); // e_type
    bytes[18..20].copy_from_slice(&(EM_ARM as u16).to_le_bytes()); // e_machine
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    bytes[28..32].copy_from_slice(&(ELF32_EHDR_SIZE as u32).to_le_bytes()); // e_phoff

    // e_flags: EABI5 | EF_ARM_ABI_FLOAT_SOFT, as required by the
    // arm_thumb_soft_float profile.
    bytes[36..40].copy_from_slice(&0x0500_0200u32.to_le_bytes());
    bytes[40..42].copy_from_slice(&(ELF32_EHDR_SIZE as u16).to_le_bytes()); // e_ehsize
    bytes[42..44].copy_from_slice(&(32u16).to_le_bytes()); // e_phentsize
    bytes[44..46].copy_from_slice(&2u16.to_le_bytes()); // e_phnum

    // PT_LOAD: r-x, covering the whole file at vaddr 0x1000. ELF32 phdr
    // field order: type, offset, vaddr, paddr, filesz, memsz, flags, align.
    let ph0 = ELF32_EHDR_SIZE;
    let file_len = bytes.len() as u32;
    bytes[ph0..ph0 + 4].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    bytes[ph0 + 4..ph0 + 8].copy_from_slice(&0u32.to_le_bytes()); // p_offset
    bytes[ph0 + 8..ph0 + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // p_vaddr
    bytes[ph0 + 12..ph0 + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // p_paddr
    bytes[ph0 + 16..ph0 + 20].copy_from_slice(&file_len.to_le_bytes()); // p_filesz
    bytes[ph0 + 20..ph0 + 24].copy_from_slice(&file_len.to_le_bytes()); // p_memsz
    bytes[ph0 + 24..ph0 + 28].copy_from_slice(&5u32.to_le_bytes()); // p_flags = R|X
    bytes[ph0 + 28..ph0 + 32].copy_from_slice(&4u32.to_le_bytes()); // p_align

    // PT_DYNAMIC uses the same ELF32 field order.
    let ph1 = ph0 + 32;
    bytes[ph1..ph1 + 4].copy_from_slice(&2u32.to_le_bytes()); // p_type = PT_DYNAMIC
    bytes[ph1 + 4..ph1 + 8].copy_from_slice(&(DYN_OFF as u32).to_le_bytes()); // p_offset
    bytes[ph1 + 8..ph1 + 12].copy_from_slice(&(0x1000 + DYN_OFF as u32).to_le_bytes()); // p_vaddr
    bytes[ph1 + 12..ph1 + 16].copy_from_slice(&(DYN_OFF as u32).to_le_bytes()); // p_paddr
    bytes[ph1 + 16..ph1 + 20].copy_from_slice(&(dyn_len as u32).to_le_bytes()); // p_filesz
    bytes[ph1 + 20..ph1 + 24].copy_from_slice(&(dyn_len as u32).to_le_bytes()); // p_memsz
    bytes[ph1 + 24..ph1 + 28].copy_from_slice(&4u32.to_le_bytes()); // p_flags = R
    bytes[ph1 + 28..ph1 + 32].copy_from_slice(&4u32.to_le_bytes()); // p_align
                                                                    // dynamic entries
    for (index, &(tag, value)) in entries.iter().enumerate() {
        let at = DYN_OFF + index * 8;
        bytes[at..at + 4].copy_from_slice(&tag.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&(value as u32).to_le_bytes());
    }
    // dynstr
    bytes[str_off..str_off + strsz].copy_from_slice(&dynstr);
    bytes
}

const DYN_OFF: usize = 52 + 2 * 32;
const ELF32_EHDR_SIZE: usize = 52;
const ET_DYN: u16 = 3;
const EM_ARM: u16 = 40;
const DT_STRTAB: u32 = 5;
const DT_STRSZ: u32 = 10;
const DT_NEEDED: u32 = 1;
const DT_SONAME: u32 = 14;
