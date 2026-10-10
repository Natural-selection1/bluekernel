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

use alloc::{sync::Arc, vec::Vec};
use core::fmt;

use crate::{
    dynamic_linker::{
        ArtifactRole, CommittingLinkProduct, DependencyResolution, ImageOwnership,
        ImportedImageDescriptor, LifecyclePlans, LinkContext, LinkProduct, LinkPublisher,
        PreparedLinkManifest, PublishedImageDescriptor, RelocationBinding,
    },
    error::{ErrorContext, LoadErrorKind},
    linker::{prepare_link, LinkRequest},
    memory::{AllocationLease, ImageProtectionMemory, TargetAddress},
    planning::{LoadPlan, PlannedResolver},
    profile::{LoadProfile, SessionLimits},
    reader::ElfReader,
    LoadError, LoadResult,
};

/// Platform services used by a complete load.
///
/// The loader owns ELF parsing, dependency traversal, scopes and relocation.
/// The backend owns file lookup policy, allocation backing and registry state.
/// The memory value must be a handle to backing that outlives the returned receipt.
pub trait LoaderBackend {
    type Source: Clone;
    type Reader: ElfReader;
    type Memory: ImageProtectionMemory;
    type PreparedPublication;
    type Receipt;

    /// Stable identity bytes for a source, including any generation policy.
    fn identity<'a>(&self, source: &'a Self::Source) -> &'a [u8];
    /// Whether the source is managed by the shared-image registry.
    /// Registry sources must be ET_DYN shared objects; executables and marked
    /// PIEs are rejected before `acquire` reserves their registry state.
    fn is_shared(&self, source: &Self::Source) -> bool;
    fn open(&mut self, source: &Self::Source) -> LoadResult<Self::Reader>;
    /// Locate one dependency. A present but invalid file must not fall back.
    fn resolve(&mut self, requester: &Self::Source, name: &[u8]) -> LoadResult<Self::Source>;
    /// Reserve the complete closure atomically before any image is mapped.
    /// Return Ready handles for these sources and retain their backing leases
    /// until publication. `existing` is already pinned by the caller, including
    /// providers whose constructors may still be running in this namespace.
    fn acquire(
        &mut self,
        sources: &[Self::Source],
        existing: &[ImageHandle],
    ) -> LoadResult<Vec<ImageHandle>>;
    fn memory(&mut self) -> Self::Memory;
    fn prepare_publication(
        &mut self,
        publication: &Publication,
    ) -> LoadResult<Self::PreparedPublication>;
    /// Transfer allocation ownership after all fallible publication work.
    ///
    /// # Safety
    /// These inputs belong to this backend's current load. This operation must
    /// not allocate, fail or panic, and must retain every allocation exactly once.
    unsafe fn commit_publication(
        &mut self,
        prepared: Self::PreparedPublication,
        allocations: CommittedAllocations,
    ) -> Self::Receipt;
    /// Install registry state using the loader's computed retention facts.
    /// On error, leave remaining allocation authority in the receipt so
    /// `abort_publication` can release it. Constructors run after `load` returns.
    fn complete_load(&mut self, _image: &mut LoadedImage<Self::Receipt>) -> LoadResult<()> {
        Ok(())
    }
    /// Release a committed receipt if completion failed before installation.
    fn abort_publication(&mut self, receipt: Self::Receipt);
    /// Cancel remaining reservations and imported references on a failed load.
    fn cancel_load(&mut self) {}
    /// Optional diagnostics; no internal graph or relocation types cross this hook.
    fn trace(&self, _message: fmt::Arguments<'_>) {}
}

/// An opaque loaded provider. Its allocation and reference counts belong to
/// the backend; holding this metadata handle does not itself pin that backing.
#[derive(Clone, Debug)]
pub struct ImageHandle {
    pub(crate) descriptor: Arc<PublishedImageDescriptor>,
    shared: bool,
}

impl ImageHandle {
    pub fn identity(&self) -> &[u8] {
        self.descriptor.identity().as_bytes()
    }
    pub const fn is_shared(&self) -> bool {
        self.shared
    }
    /// Find a visible defined export; the backend must still pin its backing.
    pub fn lookup_export(&self, name: &[u8]) -> Option<TargetAddress> {
        self.descriptor.lookup_export(name)
    }
    pub(crate) fn imported(&self) -> ImportedImageDescriptor {
        if self.shared {
            ImportedImageDescriptor::new(self.descriptor.clone())
        } else {
            ImportedImageDescriptor::namespace(self.descriptor.clone())
        }
    }
}

/// Load inputs. ELF contents determine placement, entry and dependencies.
pub struct LoadRequest<S> {
    pub(crate) source: S,
    pub(crate) profile: LoadProfile,
    pub(crate) limits: SessionLimits,
    pub(crate) existing: Vec<ImageHandle>,
    pub(crate) global: Vec<ImageHandle>,
}

impl<S> LoadRequest<S> {
    /// Load an ELF root and its complete declared dependency closure.
    /// The profile constrains the target ABI, not the ELF object type.
    pub fn new(source: S, profile: LoadProfile, limits: SessionLimits) -> Self {
        Self {
            source,
            profile,
            limits,
            existing: Vec::new(),
            global: Vec::new(),
        }
    }
    /// Supply pinned existing images and the ordered global symbol prefix.
    /// Keep them pinned through installation; `retained_images` identifies
    /// which previous owners the new result still needs.
    pub fn with_namespace(mut self, existing: Vec<ImageHandle>, global: Vec<ImageHandle>) -> Self {
        self.existing = existing;
        self.global = global;
        self
    }
}

/// Allocation counts needed by a backend to reserve its ownership sinks.
pub struct Publication {
    private: usize,
    shared: usize,
    imported: usize,
}

impl Publication {
    pub const fn private_images(&self) -> usize {
        self.private
    }
    pub const fn shared_images(&self) -> usize {
        self.shared
    }
    pub const fn imported_shared_images(&self) -> usize {
        self.imported
    }
}

/// Unique allocation authorities, paired with opaque image handles.
pub struct CommittedAllocations {
    images: Vec<ImageHandle>,
    leases: Vec<AllocationLease>,
}

impl CommittedAllocations {
    pub fn into_images(self) -> impl Iterator<Item = (ImageHandle, AllocationLease)> {
        self.images.into_iter().zip(self.leases)
    }
}

struct ImageFacts {
    handle: ImageHandle,
    newly_loaded: bool,
    lookup: Vec<ImageHandle>,
    component: Vec<ImageHandle>,
    dependencies: Vec<ImageHandle>,
    fini: Vec<usize>,
}

struct LoadFacts {
    entry: Option<TargetAddress>,
    images: Vec<ImageFacts>,
    retained: Vec<ImageHandle>,
    startup: Vec<usize>,
    fini: Vec<usize>,
    rollback_fini: Vec<usize>,
}

impl LoadFacts {
    fn metadata_bytes(&self) -> u64 {
        let handle_bytes = core::mem::size_of::<ImageHandle>();
        let mut bytes = core::mem::size_of::<Self>()
            + self.images.capacity() * core::mem::size_of::<ImageFacts>()
            + self.retained.capacity() * handle_bytes
            + (self.startup.capacity() + self.fini.capacity() + self.rollback_fini.capacity())
                * core::mem::size_of::<usize>();
        for image in &self.images {
            bytes += (image.lookup.capacity()
                + image.component.capacity()
                + image.dependencies.capacity())
                * handle_bytes;
            bytes += image.fini.capacity() * core::mem::size_of::<usize>();
        }
        bytes as u64
    }
}

/// A complete load with kernel-owned resource lifetime and opaque image metadata.
#[must_use = "the publication receipt must be installed or released"]
pub struct LoadedImage<Receipt> {
    receipt: Receipt,
    facts: LoadFacts,
}

impl<Receipt> LoadedImage<Receipt> {
    /// A validated executable entry, absent for a shared-object root.
    pub fn entry(&self) -> Option<TargetAddress> {
        self.facts.entry
    }
    /// The complete requested closure in root-first breadth-first order.
    pub fn images(&self) -> impl Iterator<Item = &ImageHandle> {
        self.facts.images.iter().map(|image| &image.handle)
    }
    /// Reused dependencies and existing providers selected by relocations,
    /// including providers found only through the global scope.
    pub fn retained_images(&self) -> &[ImageHandle] {
        &self.facts.retained
    }
    pub fn startup(&self) -> &[usize] {
        &self.facts.startup
    }
    pub fn fini(&self) -> &[usize] {
        &self.facts.fini
    }
    pub fn rollback_fini(&self) -> &[usize] {
        &self.facts.rollback_fini
    }
    pub fn is_new(&self, image: &ImageHandle) -> bool {
        self.image_facts(image)
            .is_some_and(|facts| facts.newly_loaded)
    }
    /// Root-first dependency scope for handle-based symbol lookup.
    pub fn lookup_scope(&self, image: &ImageHandle) -> &[ImageHandle] {
        self.image_facts(image)
            .map(|facts| facts.lookup.as_slice())
            .unwrap_or(&[])
    }
    /// Shared images that must be retained and quiesced as one cycle.
    pub fn shared_component(&self, image: &ImageHandle) -> &[ImageHandle] {
        self.image_facts(image)
            .map(|facts| facts.component.as_slice())
            .unwrap_or(&[])
    }
    /// Outgoing shared providers outside this image's cycle. The registry
    /// retains these; internal cycle edges must not become counted references.
    pub fn shared_dependencies(&self, image: &ImageHandle) -> &[ImageHandle] {
        self.image_facts(image)
            .map(|facts| facts.dependencies.as_slice())
            .unwrap_or(&[])
    }
    /// Validated destructors owned by a newly loaded shared instance.
    pub fn image_fini(&self, image: &ImageHandle) -> &[usize] {
        self.image_facts(image)
            .map(|facts| facts.fini.as_slice())
            .unwrap_or(&[])
    }
    /// Root program-header address, entry size and count, for the startup auxv.
    pub fn program_headers(&self) -> (Option<TargetAddress>, u16, u16) {
        let headers = self.facts.images[0].handle.descriptor.program_headers();
        (
            headers.runtime_vaddr(),
            headers.entry_size(),
            headers.count(),
        )
    }
    pub fn receipt_mut(&mut self) -> &mut Receipt {
        &mut self.receipt
    }
    pub fn into_receipt(self) -> Receipt {
        self.receipt
    }
    fn image_facts(&self, image: &ImageHandle) -> Option<&ImageFacts> {
        self.facts
            .images
            .iter()
            .find(|facts| facts.handle.identity() == image.identity())
    }
}

/// Load, link and publish the full dependency closure through platform services.
///
/// Scanning, dependency graphs, symbol scopes and retention calculations stay
/// inside the loader. Every new allocation is rolled back on pre-commit failure;
/// a completion failure returns the receipt to the backend for release.
pub fn load<B: LoaderBackend>(
    request: LoadRequest<B::Source>,
    backend: &mut B,
) -> LoadResult<LoadedImage<B::Receipt>> {
    let result = load_inner(request, backend);
    if result.is_err() {
        backend.cancel_load();
    }
    result
}

fn load_inner<B: LoaderBackend>(
    request: LoadRequest<B::Source>,
    backend: &mut B,
) -> LoadResult<LoadedImage<B::Receipt>> {
    let mut plan = LoadPlan::build(&request, backend)?;
    let sources = plan
        .images
        .iter()
        .map(|image| image.source.clone())
        .collect::<Vec<_>>();
    let ready = backend.acquire(&sources, &request.existing)?;
    let mut providers = request.existing;
    for image in ready {
        if !providers
            .iter()
            .any(|provider| provider.identity() == image.identity())
        {
            providers.push(image);
        }
    }
    let dependencies = providers
        .iter()
        .filter(|image| plan.contains(image.identity()))
        .map(ImageHandle::imported)
        .collect();
    let globals = request.global.iter().map(ImageHandle::imported).collect();
    let connections = plan.connections()?;
    let mut memory = backend.memory();
    let mut resolver = PlannedResolver {
        plan: &mut plan,
        backend,
        providers: &providers,
    };
    let role = resolver.plan.images[0].scanned.role;
    let root = match role {
        ArtifactRole::ExecutableRoot => DependencyResolution::Load(resolver.load_root()?),
        ArtifactRole::SharedObject => resolver.resolve_index(0)?,
    };
    let request = LinkRequest::new(root, role, request.profile, request.limits).with_namespace(
        globals,
        dependencies,
        connections,
    );
    let prepared = prepare_link(request, &mut resolver, &mut memory)?;
    let mut publisher = BackendPublisher {
        backend,
        plan: &plan,
        facts: None,
        allocations: Vec::new(),
    };
    let product = prepared.publish(&mut publisher)?;
    let mut facts = publisher
        .facts
        .take()
        .expect("publication prepared result metadata");
    facts.entry = (plan.images[0].scanned.role
        == crate::dynamic_linker::ArtifactRole::ExecutableRoot)
        .then(|| product.entry());
    trace_product(publisher.backend, &product);
    let mut loaded = LoadedImage {
        receipt: product.into_publication(),
        facts,
    };
    if let Err(error) = publisher.backend.complete_load(&mut loaded) {
        publisher.backend.abort_publication(loaded.into_receipt());
        return Err(error);
    }
    Ok(loaded)
}

struct BackendPublisher<'a, B: LoaderBackend> {
    backend: &'a mut B,
    plan: &'a LoadPlan<B::Source, B::Reader>,
    facts: Option<LoadFacts>,
    allocations: Vec<ImageHandle>,
}

impl<B: LoaderBackend> LinkPublisher for BackendPublisher<'_, B> {
    type PreparedBatch = B::PreparedPublication;
    type Receipt = B::Receipt;

    fn prepare_metadata(
        &mut self,
        context: &LinkContext,
        plans: &LifecyclePlans,
        bindings: &[RelocationBinding],
    ) -> LoadResult<u64> {
        self.facts = Some(build_facts(self.plan, context, plans, bindings)?);
        self.allocations
            .try_reserve_exact(context.images().len())
            .map_err(|_| oom())?;
        for image in context.images() {
            if matches!(
                image.ownership(),
                ImageOwnership::SessionPrivate | ImageOwnership::SystemCandidate
            ) {
                self.allocations.push(handle(image));
            }
        }
        let facts = self.facts.as_ref().expect("facts prepared above");
        let bytes = facts
            .metadata_bytes()
            .checked_add(self.plan.metadata_bytes()?)
            .and_then(|bytes| {
                bytes.checked_add(
                    (self.allocations.capacity() * core::mem::size_of::<ImageHandle>()) as u64,
                )
            })
            .ok_or_else(overflow)?;
        Ok(bytes)
    }
    fn prepare_batch(
        &mut self,
        manifest: &PreparedLinkManifest,
    ) -> LoadResult<Self::PreparedBatch> {
        let mut publication = Publication {
            private: 0,
            shared: 0,
            imported: 0,
        };
        for image in manifest.link_map() {
            match image.ownership() {
                ImageOwnership::SessionPrivate => publication.private += 1,
                ImageOwnership::SystemCandidate => publication.shared += 1,
                ImageOwnership::ExternalReady => publication.imported += 1,
                ImageOwnership::NamespaceReady => {}
            }
        }
        self.backend.prepare_publication(&publication)
    }
    unsafe fn commit_batch(
        &mut self,
        prepared: Self::PreparedBatch,
        product: CommittingLinkProduct,
    ) -> Self::Receipt {
        let allocations = CommittedAllocations {
            images: core::mem::take(&mut self.allocations),
            leases: product.into_leases(),
        };
        // SAFETY: the internal publisher prepared these inputs for this backend.
        unsafe { self.backend.commit_publication(prepared, allocations) }
    }
}

fn handle(image: &crate::dynamic_linker::CommittedImage) -> ImageHandle {
    ImageHandle {
        descriptor: image.descriptor_handle(),
        shared: matches!(
            image.ownership(),
            ImageOwnership::SystemCandidate | ImageOwnership::ExternalReady
        ),
    }
}

fn build_facts<S, R>(
    plan: &LoadPlan<S, R>,
    context: &LinkContext,
    plans: &LifecyclePlans,
    bindings: &[RelocationBinding],
) -> LoadResult<LoadFacts> {
    let mut facts = LoadFacts {
        entry: None,
        images: Vec::new(),
        retained: Vec::new(),
        startup: Vec::new(),
        fini: Vec::new(),
        rollback_fini: Vec::new(),
    };
    facts
        .images
        .try_reserve_exact(plan.images.len())
        .map_err(|_| oom())?;
    facts
        .retained
        .try_reserve_exact(context.images().len())
        .map_err(|_| oom())?;
    for (index, planned) in plan.images.iter().enumerate() {
        let image = context
            .images()
            .iter()
            .find(|image| image.descriptor().identity() == &planned.identity)
            .ok_or_else(invalid)?;
        let mut queue = Vec::new();
        queue
            .try_reserve_exact(plan.images.len())
            .map_err(|_| oom())?;
        queue.push(index);
        let mut cursor = 0;
        while cursor < queue.len() {
            let requester = queue[cursor];
            for edge in plan.edges.iter().filter(|edge| edge.requester == requester) {
                if !queue.contains(&edge.provider) {
                    queue.push(edge.provider);
                }
            }
            cursor += 1;
        }
        let mut lookup = Vec::new();
        lookup.try_reserve_exact(queue.len()).map_err(|_| oom())?;
        for member in queue {
            let provider = context
                .images()
                .iter()
                .find(|image| image.descriptor().identity() == &plan.images[member].identity)
                .ok_or_else(invalid)?;
            lookup.push(handle(provider));
        }
        let scc = plans
            .sccs()
            .iter()
            .find(|members| members.contains(&image.owner()))
            .ok_or_else(invalid)?;
        let mut component = Vec::new();
        let mut dependencies = Vec::new();
        component.try_reserve_exact(scc.len()).map_err(|_| oom())?;
        dependencies
            .try_reserve_exact(context.images().len())
            .map_err(|_| oom())?;
        for owner in scc {
            let member = &context.images()[owner.get() as usize];
            let member = handle(member);
            if member.shared {
                component.push(member);
            }
        }
        for edge in context
            .graph_edges()
            .iter()
            .filter(|edge| edge.requester() == image.owner() && !scc.contains(&edge.provider()))
        {
            let provider = handle(&context.images()[edge.provider().get() as usize]);
            if provider.shared
                && !dependencies
                    .iter()
                    .any(|image: &ImageHandle| image.identity() == provider.identity())
            {
                dependencies.push(provider);
            }
        }
        let mut fini = Vec::new();
        if let Some(plan) = plans
            .system_fini()
            .iter()
            .find(|plan| plan.owner() == image.owner())
        {
            copy_targets(&mut fini, plan.plan().iter())?;
        }
        let newly_loaded = matches!(
            image.ownership(),
            ImageOwnership::SessionPrivate | ImageOwnership::SystemCandidate
        );
        let image = handle(image);
        if !newly_loaded {
            facts.retained.push(image.clone());
        }
        facts.images.push(ImageFacts {
            handle: image,
            newly_loaded,
            lookup,
            component,
            dependencies,
            fini,
        });
    }
    for binding in bindings {
        if let Some(owner) = binding.provider() {
            let provider = &context.images()[owner.get() as usize];
            if matches!(
                provider.ownership(),
                ImageOwnership::ExternalReady | ImageOwnership::NamespaceReady
            ) {
                let provider = handle(provider);
                if !facts
                    .retained
                    .iter()
                    .any(|image| image.identity() == provider.identity())
                {
                    facts.retained.push(provider);
                }
            }
        }
    }
    copy_targets(&mut facts.startup, plans.startup().iter())?;
    copy_targets(&mut facts.fini, plans.group_fini().iter())?;
    facts
        .rollback_fini
        .try_reserve_exact(facts.fini.len())
        .map_err(|_| oom())?;
    facts.rollback_fini.extend_from_slice(&facts.fini);
    for plan in plans.system_fini() {
        copy_targets(&mut facts.rollback_fini, plan.plan().iter())?;
    }
    Ok(facts)
}

fn copy_targets<'a>(
    out: &mut Vec<usize>,
    entries: impl Iterator<Item = &'a crate::dynamic_linker::LifecycleEntry>,
) -> LoadResult<()> {
    for entry in entries {
        out.try_reserve(1).map_err(|_| oom())?;
        out.push(entry.function().get() as usize);
    }
    Ok(())
}

pub(crate) fn invalid() -> LoadError {
    LoadError::new(LoadErrorKind::Backend, ErrorContext::None)
}
pub(crate) fn overflow() -> LoadError {
    LoadError::new(LoadErrorKind::IntegerOverflow, ErrorContext::None)
}
pub(crate) fn oom() -> LoadError {
    LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None)
}

fn trace_product<B: LoaderBackend>(backend: &B, product: &LinkProduct<B::Receipt>) {
    let plans = product.lifecycle_plans();
    for (index, entry) in plans.startup().iter().enumerate() {
        backend.trace(format_args!(
            "LIFECYCLE_INIT index={} owner={} address={:#x}",
            index,
            entry.owner().get(),
            entry.function().get()
        ));
    }
    for (index, entry) in plans.group_fini().iter().enumerate() {
        backend.trace(format_args!(
            "LIFECYCLE_GROUP_FINI index={} owner={}",
            index,
            entry.owner().get()
        ));
    }
    for plan in plans.system_fini() {
        for entry in plan.plan().iter() {
            backend.trace(format_args!(
                "LIFECYCLE_SYSTEM_FINI owner={}",
                entry.owner().get()
            ));
        }
    }
    for edge in product.context().graph_edges() {
        backend.trace(format_args!(
            "LINK_EDGE requester={} provider={}",
            edge.requester().get(),
            edge.provider().get()
        ));
    }
    for entry in product.link_map() {
        backend.trace(format_args!(
            "LINK_MAP owner={} soname={} bias={:#x}",
            entry.owner().get(),
            entry
                .soname()
                .map(|name| core::str::from_utf8(name.as_bytes()).unwrap_or("<non-utf8>"))
                .unwrap_or("-"),
            entry.load_bias().get()
        ));
    }
    for (group, members) in plans.sccs().iter().enumerate() {
        struct Members<'a>(&'a [crate::dynamic_linker::ImageId]);
        impl fmt::Debug for Members<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list()
                    .entries(self.0.iter().map(|id| id.get()))
                    .finish()
            }
        }
        backend.trace(format_args!(
            "LIFECYCLE_SCC group={} members={:?}",
            group,
            Members(members)
        ));
    }
    for binding in product.relocation_bindings() {
        if binding.name().is_empty() {
            continue;
        }
        let name = core::str::from_utf8(binding.name()).unwrap_or("<non-utf8>");
        if let Some(provider) = binding.provider() {
            backend.trace(format_args!(
                "SCOPE_BIND requester={} name={} provider={}",
                binding.requester().get(),
                name,
                provider.get()
            ));
        } else {
            backend.trace(format_args!(
                "SCOPE_BIND requester={} name={} provider=none",
                binding.requester().get(),
                name
            ));
        }
    }
}
