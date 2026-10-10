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

use crate::{
    cache::{ArchitectureCodeCache, CacheRequirements},
    dynamic_linker::{
        ArtifactIdentity, ArtifactResolver, ArtifactRole, DependencyResolution, DynamicLinker,
        ImportedImageDescriptor, SealedSession,
    },
    memory::ImageProtectionMemory,
    profile::{LoadProfile, SessionLimits},
    reader::ElfReader,
    LoadResult,
};

#[cfg(target_arch = "aarch64")]
use crate::relocation::AArch64Relocator as PlatformRelocator;
#[cfg(target_arch = "arm")]
use crate::relocation::ArmRelocator as PlatformRelocator;
#[cfg(target_arch = "riscv32")]
use crate::relocation::Riscv32Relocator as PlatformRelocator;
#[cfg(target_arch = "riscv64")]
use crate::relocation::Riscv64Relocator as PlatformRelocator;

/// Inputs for an executable launch or a runtime shared-object load.
///
/// The kernel supplies a trusted ABI profile, resource limits and pinned
/// namespace providers. The loader selects its native relocator and owns all
/// dependency discovery, scope, relocation, cache and protection transitions.
pub(crate) struct LinkRequest<R> {
    root: DependencyResolution<R>,
    role: ArtifactRole,
    profile: LoadProfile,
    limits: SessionLimits,
    global: Vec<ImportedImageDescriptor>,
    dependencies: Vec<ImportedImageDescriptor>,
    connections: Vec<(ArtifactIdentity, ArtifactIdentity, u16)>,
}

impl<R> LinkRequest<R> {
    /// The root has already been scanned; `role` is a loader-derived fact.
    pub(crate) fn new(
        root: DependencyResolution<R>,
        role: ArtifactRole,
        profile: LoadProfile,
        limits: SessionLimits,
    ) -> Self {
        Self {
            root,
            role,
            profile,
            limits,
            global: Vec::new(),
            dependencies: Vec::new(),
            connections: Vec::new(),
        }
    }

    /// Supply the ordered global symbol scope and already loaded dependency
    /// providers. The kernel must keep their backings pinned until publication
    /// transfers that responsibility to its publisher receipt.
    pub(crate) fn with_namespace(
        mut self,
        global: Vec<ImportedImageDescriptor>,
        dependencies: Vec<ImportedImageDescriptor>,
        connections: Vec<(ArtifactIdentity, ArtifactIdentity, u16)>,
    ) -> Self {
        self.global = global;
        self.dependencies = dependencies;
        self.connections = connections;
        self
    }
}

/// Prepare the complete dependency closure for a launch or runtime load.
///
/// On success every new image is mapped, relocated, cache-synchronized and
/// sealed. The resolver retains its kernel-owned permits and provider leases;
/// the caller can hand them to its publisher before consuming the preparation
/// with [`SealedSession::publish`]. On failure all new allocations are aborted.
pub(crate) fn prepare_link<'m, R, Resolver, M>(
    request: LinkRequest<R>,
    resolver: &mut Resolver,
    memory: &'m mut M,
) -> LoadResult<SealedSession<'m, M, PlatformRelocator>>
where
    R: ElfReader,
    Resolver: ArtifactResolver,
    M: ImageProtectionMemory + ?Sized,
{
    let LinkRequest {
        root,
        role,
        profile,
        limits,
        global,
        dependencies,
        connections,
    } = request;
    let linker = DynamicLinker::new(PlatformRelocator);
    let mut session = linker.begin(root, role, profile, limits, memory)?;
    session.import_scope(global)?;
    session.close_dependencies(resolver)?;
    session.import_dependencies(dependencies)?;
    session.connect_dependencies(&connections)?;
    let mut cache = ArchitectureCodeCache::new(CacheRequirements::CURRENT_EXECUTION_CONTEXT);
    session.freeze_scopes()?.relocate()?.seal(&mut cache)
}
