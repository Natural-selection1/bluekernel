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

use alloc::vec::Vec;

use blueos_test_macro::test;
use goblin::elf::header::{EM_AARCH64, EM_ARM, EM_RISCV, ET_DYN};

use crate::{
    dynamic_linker::{
        ArtifactIdentity, ArtifactResolver, ArtifactRole, CommittingLinkProduct, DependencyRequest,
        DependencyResolution, ImageOwnership, LinkPublisher, PreparedLinkManifest,
        ResolvedArtifact,
    },
    error::{ErrorContext, LoadErrorKind, LoadStage},
    linker::{prepare_link, LinkRequest},
    memory::{
        AllocationLease, AllocationRequest, ImageMemory, MemoryMapper, MutationProgress, Placement,
    },
    profile::{LoadProfile, SessionLimits},
    tests::fixture::{ElfFixtureBuilder, SliceElfReader},
    LoadError, LoadResult,
};

pub(super) fn native_fixture() -> (Vec<u8>, LoadProfile) {
    #[cfg(target_arch = "arm")]
    let (fixture, profile, flags, entry) = (
        ElfFixtureBuilder::elf32(EM_ARM, ET_DYN),
        LoadProfile::arm_thumb_soft_float(),
        0x0500_0200,
        0x1001,
    );
    #[cfg(target_arch = "riscv32")]
    let (fixture, profile, flags, entry) = (
        ElfFixtureBuilder::elf32(EM_RISCV, ET_DYN),
        LoadProfile::riscv32(),
        0,
        0x1000,
    );
    #[cfg(target_arch = "riscv64")]
    let (fixture, profile, flags, entry) = (
        ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN),
        LoadProfile::riscv64(),
        0,
        0x1000,
    );
    #[cfg(target_arch = "aarch64")]
    let (fixture, profile, flags, entry) = (
        ElfFixtureBuilder::elf64(EM_AARCH64, ET_DYN),
        LoadProfile::aarch64(),
        0,
        0x1000,
    );
    (
        fixture
            .with_flags(flags)
            .with_load_segment(0x1000, 0x100, 0x100, 4)
            .with_entry(entry)
            .build(),
        profile,
    )
}

fn request(bytes: &[u8], profile: LoadProfile) -> LinkRequest<SliceElfReader<'_>> {
    LinkRequest::new(
        DependencyResolution::Load(ResolvedArtifact::new(
            ArtifactIdentity::from_bytes(b"native-root").unwrap(),
            ImageOwnership::SessionPrivate,
            SliceElfReader::new(bytes),
        )),
        ArtifactRole::ExecutableRoot,
        profile,
        SessionLimits::DEFAULT,
    )
}

struct NoDependencies;

impl ArtifactResolver for NoDependencies {
    type Reader = SliceElfReader<'static>;

    fn resolve(
        &mut self,
        _: &DependencyRequest<'_>,
    ) -> LoadResult<DependencyResolution<Self::Reader>> {
        panic!("fixture has no dependencies")
    }
}

#[derive(Default)]
struct Publisher {
    reject: bool,
    commits: usize,
}

impl LinkPublisher for Publisher {
    type PreparedBatch = ();
    type Receipt = Vec<AllocationLease>;

    fn prepare_batch(&mut self, _: &PreparedLinkManifest) -> LoadResult<()> {
        if self.reject {
            Err(LoadError::new(LoadErrorKind::Backend, ErrorContext::None))
        } else {
            Ok(())
        }
    }

    unsafe fn commit_batch(&mut self, _: (), product: CommittingLinkProduct) -> Self::Receipt {
        self.commits += 1;
        product.into_leases()
    }
}

fn assert_memory_reusable(memory: &mut MemoryMapper) {
    let lease = memory
        .allocate_image(AllocationRequest::new(Placement::Anywhere, 16, 4))
        .expect("preparation must have rolled back its allocation");
    memory.abort_image(lease, MutationProgress::Reserved);
}

#[test]
fn prepared_link_drop_rolls_back_allocation() {
    let (bytes, profile) = native_fixture();
    let mut memory = MemoryMapper::new(None);
    let prepared = prepare_link(request(&bytes, profile), &mut NoDependencies, &mut memory)
        .expect("prepare complete link");
    drop(prepared);
    assert_memory_reusable(&mut memory);
}

#[test]
fn prepared_link_publish_transfers_allocation_once() {
    let (bytes, profile) = native_fixture();
    let mut memory = MemoryMapper::new(None);
    let mut publisher = Publisher::default();
    let prepared = prepare_link(request(&bytes, profile), &mut NoDependencies, &mut memory)
        .expect("prepare complete link");
    assert_eq!(publisher.commits, 0);
    let product = prepared.publish(&mut publisher).expect("publish");
    assert_eq!(publisher.commits, 1);
    assert_eq!(product.context().images().len(), 1);
    assert!(product.entry().get() != 0);
    let mut leases = product.into_publication();
    assert_eq!(leases.len(), 1);
    memory.release_committed(leases.pop().unwrap());
    assert_memory_reusable(&mut memory);
}

#[test]
fn prepared_link_publish_failure_rolls_back_allocation() {
    let (bytes, profile) = native_fixture();
    let mut memory = MemoryMapper::new(None);
    let mut publisher = Publisher {
        reject: true,
        commits: 0,
    };
    let prepared = prepare_link(request(&bytes, profile), &mut NoDependencies, &mut memory)
        .expect("prepare complete link");
    let error = prepared
        .publish(&mut publisher)
        .err()
        .expect("publisher rejects");
    assert!(matches!(error.kind(), LoadErrorKind::Backend));
    assert!(matches!(error.stage(), Some(LoadStage::Publish)));
    assert_eq!(publisher.commits, 0);
    assert_memory_reusable(&mut memory);
}
