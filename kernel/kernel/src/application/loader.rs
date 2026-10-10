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

//! Kernel services for the loader's complete-load interface.
//! File policy, backing ownership and registry state stay in the kernel;
//! dependency graphs, binding decisions and lifecycle plans stay in the loader.

use crate::application::{
    adapters::{
        flat_memory::FlatImageMemory,
        resolver::{KernelSource, NamespaceSourceResolver},
        system_paths::{SystemLibraryKey, SystemLibraryPaths},
        vfs_reader::VfsElfReader,
    },
    group::{GroupState, ThreadGroup},
    namespace::ApplicationNamespace,
    publication::{KernelLinkPreparedBatch, KernelLinkPublisher, KernelLinkReceipt},
    registry::{
        AcquireBatchOutcome, LoadPermit, PreparedSystemBatch, SystemCandidateBacking,
        SystemDsoLease, SystemDsoRegistry, SystemInitBatch,
    },
};
use alloc::vec::Vec;
use blueos_loader::{
    error::{ErrorContext, LoadErrorKind},
    load,
    memory::ImageMemory,
    profile::SessionLimits,
    CommittedAllocations, ImageHandle, LoadError, LoadRequest, LoadResult, LoadedImage,
    LoaderBackend, Publication,
};

pub struct ApplicationLoader {
    catalog: &'static SystemLibraryPaths,
    registry: SystemDsoRegistry,
    memory: FlatImageMemory,
}

impl ApplicationLoader {
    pub fn new(
        catalog: &'static SystemLibraryPaths,
        registry: SystemDsoRegistry,
        memory: FlatImageMemory,
    ) -> Self {
        Self {
            catalog,
            registry,
            memory,
        }
    }
    pub fn registry(&self) -> &SystemDsoRegistry {
        &self.registry
    }
    pub fn catalog(&self) -> &'static SystemLibraryPaths {
        self.catalog
    }
    pub fn memory(&self) -> &FlatImageMemory {
        &self.memory
    }

    pub fn link(
        &self,
        namespace: &ApplicationNamespace,
        group: &ThreadGroup,
    ) -> LoadResult<LoadedImage<KernelLinkReceipt>> {
        let mut backend = KernelLoaderBackend::new(self, namespace, group, false);
        let source = backend.files.root(namespace.root_path(), true);
        load(
            LoadRequest::new(source, namespace.profile(), SessionLimits::DEFAULT),
            &mut backend,
        )
    }
    pub(crate) fn link_shared(
        &self,
        namespace: &ApplicationNamespace,
        path: &str,
        group: &ThreadGroup,
        existing: Vec<ImageHandle>,
        global: Vec<ImageHandle>,
    ) -> LoadResult<(LoadedImage<KernelLinkReceipt>, SystemInitBatch)> {
        let mut backend = KernelLoaderBackend::new(self, namespace, group, true);
        let source = backend.files.root(path, false);
        let request = LoadRequest::new(source, namespace.profile(), SessionLimits::DEFAULT)
            .with_namespace(existing, global);
        let product = load(request, &mut backend)?;
        Ok((
            product,
            backend
                .batch
                .take()
                .expect("completed runtime load installs its batch"),
        ))
    }
}

struct KernelLoaderBackend<'a> {
    loader: &'a ApplicationLoader,
    files: NamespaceSourceResolver<'a>,
    group: ThreadGroup,
    publisher: KernelLinkPublisher,
    permits: Vec<(SystemLibraryKey, LoadPermit)>,
    leases: Vec<SystemDsoLease>,
    batch: Option<SystemInitBatch>,
    runtime: bool,
}

impl<'a> KernelLoaderBackend<'a> {
    fn new(
        loader: &'a ApplicationLoader,
        namespace: &'a ApplicationNamespace,
        group: &ThreadGroup,
        runtime: bool,
    ) -> Self {
        Self {
            loader,
            files: NamespaceSourceResolver::new(namespace, loader.catalog),
            group: group.clone(),
            publisher: KernelLinkPublisher::new(loader.memory.clone()),
            permits: Vec::new(),
            leases: Vec::new(),
            batch: None,
            runtime,
        }
    }

    fn hand_off(
        &mut self,
        product: &mut LoadedImage<KernelLinkReceipt>,
    ) -> LoadResult<SystemInitBatch> {
        let images = product.receipt_mut().system_images().to_vec();
        if self.permits.len() != images.len() {
            return Err(loader_error());
        }
        // Prepare every fallible metadata copy before taking allocation ownership.
        let mut metadata = Vec::new();
        metadata
            .try_reserve_exact(images.len())
            .map_err(|_| loader_oom())?;
        let mut relocated = Vec::new();
        relocated
            .try_reserve_exact(images.len())
            .map_err(|_| loader_oom())?;
        let mut backings = Vec::new();
        backings
            .try_reserve_exact(images.len())
            .map_err(|_| loader_oom())?;
        for image in &images {
            let key = SystemLibraryKey::from_bytes(image.identity())?;
            let keep_cached = self
                .loader
                .catalog
                .resolve_key(&key)
                .ok_or_else(loader_error)?
                .keep_cached;
            let mut scc_members = image_keys(product.shared_component(image))?;
            if scc_members.is_empty() {
                return Err(loader_error());
            }
            scc_members.sort();
            scc_members.dedup();
            let mut dependency_keys = image_keys(product.shared_dependencies(image))?;
            dependency_keys.sort();
            dependency_keys.dedup();
            let mut dependencies = Vec::new();
            dependencies
                .try_reserve_exact(dependency_keys.len())
                .map_err(|_| loader_oom())?;
            let mut fini = Vec::new();
            fini.try_reserve_exact(product.image_fini(image).len())
                .map_err(|_| loader_oom())?;
            fini.extend_from_slice(product.image_fini(image));
            metadata.push((
                fini,
                dependency_keys,
                dependencies,
                scc_members,
                keep_cached,
            ));
            let index = self
                .permits
                .iter()
                .position(|(candidate, _)| candidate == &key)
                .ok_or_else(loader_error)?;
            let (_, permit) = self.permits.swap_remove(index);
            relocated.push(self.loader.registry.publish_relocated(permit)?);
        }
        let (images, allocations) = product.receipt_mut().take_system_backings();
        for (
            (descriptor, allocation),
            (fini_plan, dependency_keys, dependencies, scc_members, keep_cached),
        ) in images.into_iter().zip(allocations).zip(metadata)
        {
            backings.push(SystemCandidateBacking {
                descriptor,
                allocation,
                fini_plan,
                dependency_keys,
                dependencies,
                scc_members,
                keep_cached,
            });
        }
        let result = self
            .loader
            .registry
            .publish_relocated_batch(relocated, &mut backings);
        // Failed publication leaves ownership with us; successful publication drains it.
        if result.is_err() {
            let mut memory = self.loader.memory.clone();
            for backing in backings {
                memory.release_committed(backing.allocation);
            }
        }
        result
    }
}

impl LoaderBackend for KernelLoaderBackend<'_> {
    type Source = KernelSource;
    type Reader = VfsElfReader;
    type Memory = FlatImageMemory;
    type PreparedPublication = KernelLinkPreparedBatch;
    type Receipt = KernelLinkReceipt;

    fn identity<'a>(&self, source: &'a KernelSource) -> &'a [u8] {
        source.path().as_bytes()
    }
    fn is_shared(&self, source: &KernelSource) -> bool {
        source.shared()
    }
    fn open(&mut self, source: &KernelSource) -> LoadResult<VfsElfReader> {
        self.files.open(source)
    }
    fn resolve(&mut self, requester: &KernelSource, name: &[u8]) -> LoadResult<KernelSource> {
        self.files.resolve(requester, name)
    }
    fn acquire(
        &mut self,
        sources: &[KernelSource],
        existing: &[ImageHandle],
    ) -> LoadResult<Vec<ImageHandle>> {
        let mut keys = Vec::new();
        keys.try_reserve_exact(sources.len())
            .map_err(|_| loader_oom())?;
        for source in sources {
            // Constructors may dlopen while their startup batch is Initializing.
            // Reuse its pinned handles instead of waiting for our own completion.
            if source.shared()
                && !existing
                    .iter()
                    .any(|image| image.identity() == source.path().as_bytes())
            {
                keys.push(SystemLibraryKey::from_bytes(source.path().as_bytes())?);
            }
        }
        keys.sort();
        keys.dedup();
        let PreparedSystemBatch { loads, imports } = loop {
            match self.loader.registry.acquire_batch(&keys) {
                AcquireBatchOutcome::Acquired(batch) => break batch,
                AcquireBatchOutcome::Pending(wait) => wait.wait(),
            }
        };
        self.permits = loads;
        let mut handles = Vec::new();
        handles
            .try_reserve_exact(imports.len())
            .map_err(|_| loader_oom())?;
        self.leases
            .try_reserve_exact(imports.len())
            .map_err(|_| loader_oom())?;
        for (_, lease, image) in imports {
            self.leases.push(lease);
            handles.push(image);
        }
        Ok(handles)
    }
    fn memory(&mut self) -> FlatImageMemory {
        self.loader.memory.clone()
    }
    fn prepare_publication(
        &mut self,
        publication: &Publication,
    ) -> LoadResult<KernelLinkPreparedBatch> {
        if !self.runtime
            && (self.group.state() != GroupState::New
                || publication.imported_shared_images() != self.leases.len())
        {
            return Err(loader_error());
        }
        self.publisher
            .import_leases(core::mem::take(&mut self.leases));
        self.publisher.prepare(publication)
    }
    unsafe fn commit_publication(
        &mut self,
        prepared: KernelLinkPreparedBatch,
        allocations: CommittedAllocations,
    ) -> KernelLinkReceipt {
        self.publisher.commit(prepared, allocations)
    }
    fn complete_load(&mut self, image: &mut LoadedImage<KernelLinkReceipt>) -> LoadResult<()> {
        let batch = self.hand_off(image)?;
        if self.runtime {
            self.batch = Some(batch);
        } else {
            self.group
                .install_pending_system_batch(batch)
                .map_err(|_| loader_error())?;
        }
        Ok(())
    }
    fn abort_publication(&mut self, receipt: KernelLinkReceipt) {
        drop(receipt);
    }
    fn cancel_load(&mut self) {
        self.permits.clear();
        self.leases.clear();
        self.publisher.cancel();
    }
    fn trace(&self, message: core::fmt::Arguments<'_>) {
        log::info!("{}", message);
    }
}

fn image_keys(images: &[ImageHandle]) -> LoadResult<Vec<SystemLibraryKey>> {
    let mut keys = Vec::new();
    keys.try_reserve_exact(images.len())
        .map_err(|_| loader_oom())?;
    for image in images {
        keys.push(SystemLibraryKey::from_bytes(image.identity())?);
    }
    Ok(keys)
}
fn loader_error() -> LoadError {
    LoadError::new(LoadErrorKind::Backend, ErrorContext::None)
}
fn loader_oom() -> LoadError {
    LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None)
}
