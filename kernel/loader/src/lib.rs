// Copyright (c) 2025 vivo Mobile Communication Co., Ltd.
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

#![no_std]
#![no_main]
#![cfg_attr(test, feature(custom_test_frameworks))]
#![cfg_attr(test, test_runner(loader_test_runner))]
#![cfg_attr(test, reexport_test_harness_main = "loader_test_main")]
#![feature(c_size_t)]
#![feature(let_chains)]

extern crate alloc;

mod address;
mod cache;
mod dynamic_linker;
mod elf;
mod error;
mod identity;
mod image;
mod memory;
mod memory_mapper;
mod reader;
mod relocation;

use goblin::elf::header::{
    EI_CLASS, EI_DATA, ELFCLASS32, ELFCLASS64, ELFDATA2LSB, ELFDATA2MSB, EM_AARCH64, EM_ARM,
    EM_RISCV,
};
use image::{read_u16, ImageLoader};
use memory_mapper::MappingMode;
use reader::SliceElfReader;

pub use address::{TargetAddress, TargetRange};
pub use cache::{
    ArchitectureCodeCache, CacheMaintenance, CacheRequirements, CacheSyncOutcome, CodeCache,
    ExecutionScope, PreparedCacheSync,
};
pub use dynamic_linker::{
    ArtifactIdentity, ArtifactResolver, ArtifactRole, BuildingSession, CommittedImage,
    CommittingLinkProduct, DependencyName, DependencyRequest, DependencyRequester,
    DependencyResolution, DynamicLinker, FileIdentity, FiniPlan, ImageFiniPlan, ImageId,
    ImageOwnership, ImportedImageDescriptor, InitPlan, LifecycleEntry, LifecyclePlans, LinkContext,
    LinkMapEntry, LinkProduct, LinkPublisher, LinkSession, PreparedLinkManifest,
    ProgramHeaderRuntimeInfo, PublishedImageDescriptor, PublishedRegion, PublishedSymbolTable,
    RelocatedSession, RelocationBinding, ResolvedArtifact, ScopedSession, SealedSession,
};
pub use error::{
    ErrorContext, HeaderField, LimitKind, LoadError, LoadErrorKind, LoadResult, LoadStage,
    ProgramHeaderField,
};
pub use identity::{
    ElfClass, ElfData, ElfMachine, ElfType, EntryMode, HeaderFlagsPolicy, LoadLimits, LoadProfile,
    LoadRequest, SessionLimits,
};
pub use image::{
    scan_artifact, AppliedProtectionSet, PreparedProtectionPlan, ProtectionBatch,
    ProtectionCapabilities, ProtectionLevel, ProtectionRecord, ScannedArtifact, SealPlan,
    SealRange, SealedState,
};
pub use memory::{
    AllocationId, AllocationLease, AllocationOffset, AllocationOwnership, AllocationRequest,
    ImageAllocation, ImageCommitMemory, ImageMemory, ImageProtectionMemory, MutationProgress,
    Placement,
};
pub use memory_mapper::{MemoryMapper, MemoryPermissions, MemoryRegion};
pub use reader::ElfReader;
pub use relocation::{
    AArch64Relocator, AddendEncoding, ArchRelocator, ArmRelocator, Riscv32Relocator,
    Riscv64Relocator,
};

/// A fully mapped, relocated, cache-synchronized and sealed image that has
/// not yet been published by the kernel.
///
/// This value exclusively borrows the memory backend and keeps the unique
/// allocation lease armed. Dropping it aborts the image; successful
/// publication must go through `prepare_commit()` and `ReadyImageCommit`.
#[must_use = "dropping a prepared image aborts its allocation"]
pub struct PreparedImage<'m, M: ImageMemory + ?Sized> {
    transaction: memory::ImageLoadTransaction<&'m mut M>,
    sealed: SealedState,
}

impl<'m, M: ImageCommitMemory + ?Sized> PreparedImage<'m, M> {
    pub fn prepare_commit(mut self) -> LoadResult<ReadyImageCommit<'m, M>> {
        let allocation = *self.transaction.allocation();
        let install = (**self.transaction.memory_mut())
            .prepare_install(&allocation, &self.sealed)
            .map_err(|error| error.at_stage(LoadStage::Publish))?;
        Ok(ReadyImageCommit {
            transaction: self.transaction,
            sealed: self.sealed,
            install,
        })
    }
}

#[must_use = "dropping a ready image commit still aborts its allocation"]
pub struct ReadyImageCommit<'m, M: ImageCommitMemory + ?Sized> {
    transaction: memory::ImageLoadTransaction<&'m mut M>,
    sealed: SealedState,
    install: M::PreparedInstall,
}

impl<M: ImageCommitMemory + ?Sized> ReadyImageCommit<'_, M> {
    /// Atomically installs the already prepared state and transfers the
    /// allocation lease into the backend's committed owner.
    pub fn commit(self) -> M::CommitReceipt {
        let Self {
            mut transaction,
            sealed,
            install,
        } = self;
        let lease = transaction.take_lease();
        // SAFETY: all three values were produced by this transaction and its
        // same exclusively borrowed backend. `prepare_install` completed all
        // fallible work before the lease was disarmed.
        unsafe { (**transaction.memory_mut()).commit_install(install, sealed, lease) }
    }
}

/// Prepare one image using a profile and platform backends supplied by the
/// kernel.
///
/// Unlike the compatibility [`load_elf`] entry point, this function never
/// derives a trusted profile from the artifact and never takes ownership of
/// the memory backend. On success the returned `PreparedImage` keeps an
/// exclusive borrow until it is committed or dropped; on failure the same
/// transaction aborts any allocation before returning the borrow.
pub fn prepare_image<'m, R, M, C, A>(
    reader: R,
    request: LoadRequest,
    memory: &'m mut M,
    cache: &mut C,
    relocator: &A,
) -> LoadResult<PreparedImage<'m, M>>
where
    R: ElfReader,
    M: ImageProtectionMemory + ?Sized,
    C: CodeCache + ?Sized,
    A: ArchRelocator + ?Sized,
{
    if request.profile().machine() != relocator.machine()
        || request.profile().class() != relocator.class()
    {
        return Err(
            LoadError::new(LoadErrorKind::UnsupportedByProfile, ErrorContext::None)
                .at_stage(LoadStage::Beginning),
        );
    }

    let sealed = ImageLoader::new(reader, request)
        .admit()?
        .inspect()?
        .plan()?
        .allocate(memory)?
        .map()?
        .decode()?
        .relocation(relocator)?
        .cache(cache)?
        .seal()?;
    let (transaction, sealed) = sealed.into_prepared_parts();
    Ok(PreparedImage {
        transaction,
        sealed,
    })
}

/// Bytes needed to peek at EI_CLASS, EI_DATA and e_machine before the
/// pipeline takes over (e_machine ends at offset 20).
const PROFILE_PEEK_LEN: u64 = 20;

fn peek_profile(reader: &dyn ElfReader, expected_type: ElfType) -> LoadResult<LoadProfile> {
    let mut peek = [0; PROFILE_PEEK_LEN as usize];
    reader
        .read_exact_at(0, &mut peek)
        .map_err(|error| error.at_stage(LoadStage::Admit))?;
    let class = match peek[EI_CLASS] {
        ELFCLASS32 => ElfClass::Elf32,
        ELFCLASS64 => ElfClass::Elf64,
        value => {
            return Err(LoadError::new(
                LoadErrorKind::BadElf,
                ErrorContext::HeaderField {
                    field: HeaderField::Class,
                    value: u64::from(value),
                },
            )
            .at_stage(LoadStage::Admit));
        }
    };
    let endian = match peek[EI_DATA] {
        ELFDATA2LSB => ElfData::Little,
        ELFDATA2MSB => ElfData::Big,
        value => {
            return Err(LoadError::new(
                LoadErrorKind::BadElf,
                ErrorContext::HeaderField {
                    field: HeaderField::Endian,
                    value: u64::from(value),
                },
            )
            .at_stage(LoadStage::Admit));
        }
    };
    let machine =
        match read_u16(&peek, 18, endian).map_err(|error| error.at_stage(LoadStage::Admit))? {
            EM_ARM => ElfMachine::Arm,
            EM_RISCV => ElfMachine::Riscv,
            EM_AARCH64 => ElfMachine::Aarch64,
            value => ElfMachine::Other(value),
        };
    // The compatibility entry point derives its profile from the artifact, so
    // it cannot assert a board ABI: accept any `e_flags` and only enforce the
    // entry-mode geometry for the recognized machines.
    let (flags, entry_mode) = match machine {
        ElfMachine::Arm => (
            identity::HeaderFlagsPolicy::permissive(),
            EntryMode::thumb(2, 2),
        ),
        ElfMachine::Riscv => (
            identity::HeaderFlagsPolicy::permissive(),
            EntryMode::direct(2, 2),
        ),
        ElfMachine::Aarch64 => (
            identity::HeaderFlagsPolicy::permissive(),
            EntryMode::direct(4, 4),
        ),
        ElfMachine::Other(_) => (
            identity::HeaderFlagsPolicy::permissive(),
            EntryMode::direct(1, 1),
        ),
    };
    Ok(LoadProfile::new(
        class,
        endian,
        machine,
        expected_type,
        flags,
        entry_mode,
    ))
}

fn expected_type_for(mapper: &MemoryMapper) -> ElfType {
    match mapper.mapping_mode() {
        MappingMode::Allocated => ElfType::Dyn,
        MappingMode::Fixed(_) => ElfType::Exec,
    }
}

/// Compatibility entry point for loading from a seek-based reader.
///
/// New kernel code should construct a trusted [`LoadRequest`] and call
/// [`prepare_image`] instead. This wrapper derives a compatibility profile
/// from the artifact because the legacy API has no profile parameter.
pub fn load_elf_from_reader<R: ElfReader>(reader: R, mapper: &mut MemoryMapper) -> LoadResult<()> {
    let expected_type = expected_type_for(mapper);
    let profile = peek_profile(&reader, expected_type)?;
    let (class, machine) = (profile.class(), profile.machine());
    let request = LoadRequest::new(profile, LoadLimits::DEFAULT);

    let mut cache = ArchitectureCodeCache::new(CacheRequirements::CURRENT_EXECUTION_CONTEXT);
    let prepared = match (machine, class) {
        (ElfMachine::Arm, ElfClass::Elf32) => {
            prepare_image(reader, request, mapper, &mut cache, &ArmRelocator)
        }
        (ElfMachine::Riscv, ElfClass::Elf32) => {
            prepare_image(reader, request, mapper, &mut cache, &Riscv32Relocator)
        }
        (ElfMachine::Riscv, ElfClass::Elf64) => {
            prepare_image(reader, request, mapper, &mut cache, &Riscv64Relocator)
        }
        (ElfMachine::Aarch64, ElfClass::Elf64) => {
            prepare_image(reader, request, mapper, &mut cache, &AArch64Relocator)
        }
        _ => Err(LoadError::new(
            LoadErrorKind::UnsupportedByProfile,
            ErrorContext::HeaderField {
                field: HeaderField::Machine,
                value: u64::from(machine),
            },
        )
        .at_stage(LoadStage::Beginning)),
    }?;

    let _receipt = prepared.prepare_commit()?.commit();
    Ok(())
}

/// Load an ELF image through the unified ImageLoader pipeline.
///
/// `mapper` decides the image kind: an Allocated mapper accepts movable
/// ET_DYN images on the heap, a Fixed mapper accepts ET_EXEC images inside
/// its static regions. Either way the same parser, copy algorithm and
/// relocation stages run.
pub fn load_elf(buffer: &[u8], mapper: &mut MemoryMapper) -> LoadResult<()> {
    load_elf_from_reader(SliceElfReader::new(buffer), mapper)
}

#[cfg(test)]
extern crate rsrt;

#[cfg(test)]
use alloc::sync::Arc;
#[cfg(test)]
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(test)]
mod tests;

#[cfg(test)]
pub fn loader_test_runner(tests: &[&dyn Fn()]) {
    semihosting::println!("Loader unittest started");
    semihosting::println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
    semihosting::println!("Loader unittest ended");

    #[cfg(coverage)]
    blueos::coverage::write_coverage_data();
}

#[cfg(test)]
fn run_loader_tests_on_own_stack() {
    // Debug builds can overflow the 12 KiB main-thread stack in loader decode paths.
    const STACK_SIZE: usize = 64 * 1024;

    let done = Arc::new(AtomicUsize::new(0));
    let worker_done = done.clone();
    let worker = blueos::thread::spawn_with_stack(STACK_SIZE, move || {
        librs::pthread::register_my_posix_tcb();
        loader_test_main();
        worker_done.store(1, Ordering::Release);
        let _ = blueos::sync::atomic_wake(&worker_done, usize::MAX);
    });
    assert!(
        worker.is_some(),
        "loader unittest: no {STACK_SIZE}-byte stack"
    );

    while done.load(Ordering::Acquire) == 0 {
        let _ = blueos::sync::atomic_wait(&done, 0, blueos::time::Tick::MAX);
    }
}

#[cfg(test)]
#[no_mangle]
extern "C" fn main() -> i32 {
    librs::pthread::register_my_posix_tcb();
    run_loader_tests_on_own_stack();
    0
}
