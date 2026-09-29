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

//! Application-owned runtime namespace. A batch owns the newly mapped closure;
//! references to older batches keep borrowed dependencies and relocation
//! providers alive. Unreachable batches unload in reverse load order. This
//! deliberately permits retaining a dependency's whole original batch until
//! its last user closes, rather than splitting a committed allocation receipt.
//!
//! An operation gate serializes threads but is recursive for its owner. Its
//! ownership spans the user-side init/fini plan; no spinlock spans user code.
//! Two-phase operation tokens are thread-owned, checked in nesting order, and
//! keep every function array/backing pinned until DlFinish.

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

use blueos_header::dlfcn::{BlueOsDlPlan, RTLD_GLOBAL, RTLD_LAZY, RTLD_NOW};
use blueos_loader::{
    ArtifactIdentity, ImageOwnership, LinkContext, LinkProduct, PublishedImageDescriptor,
};

use crate::{
    application::{
        adapters::resolver::identity_from_path,
        group::{GroupState, ThreadGroup},
        namespace::{resolve_dependency_paths, ApplicationNamespace, DependencyKind, ResolveBase},
        planner::{NamespaceLoadPlan, NamespaceLoadPlanner},
        publication::KernelLinkReceipt,
        registry::SystemInitBatch,
        service::ApplicationService,
    },
    sync::SpinLock,
    time::Tick,
};

static NEXT_TOKEN: AtomicUsize = AtomicUsize::new(1);
type Result<T> = core::result::Result<T, i32>;

fn token() -> Result<usize> {
    NEXT_TOKEN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            (next < isize::MAX as usize).then_some(next + 1)
        })
        .map_err(|_| libc::EOVERFLOW)
}

struct Object {
    handle: usize,
    descriptor: Arc<PublishedImageDescriptor>,
    system: bool,
    global: bool,
    opens: usize,
    // Root-first BFS closure for dlsym(handle), independent of global scope.
    lookup: Vec<Arc<PublishedImageDescriptor>>,
}

pub(crate) struct ExistingImage {
    descriptor: Arc<PublishedImageDescriptor>,
    system: bool,
    global: bool,
    batch: usize,
}

struct Batch {
    id: usize,
    objects: Vec<Object>,
    dependencies: Vec<usize>,
    fini: Box<[usize]>,
    rollback_fini: Box<[usize]>,
    receipt: Option<KernelLinkReceipt>,
    initializing: bool,
}

impl Drop for Batch {
    fn drop(&mut self) {
        if let Some(receipt) = self.receipt.take() {
            // Batches are removed under the namespace lock and dropped outside
            // it. At abnormal group exit the reaper skips private fini, then
            // releases the same receipts after all member threads retired.
            if let Some(service) = ApplicationService::get() {
                service.release_runtime_receipt(receipt);
            }
        }
    }
}

enum OperationKind {
    Open {
        batch: usize,
        system: SystemInitBatch,
    },
    Close {
        batches: Vec<Batch>,
    },
}

struct Operation {
    token: usize,
    handle: usize,
    entries: Box<[usize]>,
    error: i32,
    kind: OperationKind,
}

impl Operation {
    fn plan(&self) -> BlueOsDlPlan {
        BlueOsDlPlan {
            handle: self.handle,
            token: self.token,
            entries: self.entries.as_ptr(),
            count: self.entries.len(),
            error: self.error,
            ..BlueOsDlPlan::empty()
        }
    }
}

struct State {
    base: Vec<Object>,
    batches: Vec<Batch>,
    pending: Vec<Operation>,
    depth: usize,
    exiting: bool,
}

pub struct RuntimeNamespace {
    namespace: ApplicationNamespace,
    owner: AtomicUsize,
    state: SpinLock<State>,
}

struct Gate<'a> {
    runtime: &'a RuntimeNamespace,
    armed: bool,
}

impl Gate<'_> {
    fn hand_off(mut self) {
        self.armed = false;
    }
}

impl Drop for Gate<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.runtime.leave();
        }
    }
}

pub(crate) struct PreparedLoad {
    batch: Batch,
    init: Box<[usize]>,
    system: SystemInitBatch,
}

impl RuntimeNamespace {
    pub(crate) fn new(
        namespace: ApplicationNamespace,
        product: &LinkProduct<KernelLinkReceipt>,
    ) -> Result<Arc<Self>> {
        let context = product.context();
        let mut base = Vec::new();
        for image in context.images() {
            base.push(Object {
                handle: token()?,
                descriptor: image.descriptor_handle(),
                system: image.ownership() != ImageOwnership::SessionPrivate,
                global: true,
                opens: 0,
                lookup: context_closure(context, image.owner().get() as usize),
            });
        }
        Ok(Arc::new(Self {
            namespace,
            owner: AtomicUsize::new(0),
            state: SpinLock::new(State {
                base,
                batches: Vec::new(),
                pending: Vec::new(),
                depth: 0,
                exiting: false,
            }),
        }))
    }

    fn enter(&self, thread: usize) -> Gate<'_> {
        loop {
            let owner = self.owner.load(Ordering::Acquire);
            if owner == thread
                || (owner == 0
                    && self
                        .owner
                        .compare_exchange(0, thread, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok())
            {
                self.state.irqsave_lock().depth += 1;
                return Gate {
                    runtime: self,
                    armed: true,
                };
            }
            let _ = crate::sync::atomic_wait(&self.owner, owner, Tick::MAX);
        }
    }

    fn leave(&self) {
        let mut state = self.state.irqsave_lock();
        state.depth -= 1;
        let last = state.depth == 0;
        if last {
            if state.batches.is_empty() {
                state.batches = Vec::new();
            }
            if state.pending.is_empty() {
                state.pending = Vec::new();
            }
            self.owner.store(0, Ordering::Release);
        }
        drop(state);
        if last {
            let _ = crate::sync::atomic_wake(&self.owner, usize::MAX);
        }
    }

    pub(crate) fn open(
        &self,
        group: &ThreadGroup,
        path: Option<&str>,
        cwd: &str,
        flags: i32,
        thread: usize,
    ) -> Result<BlueOsDlPlan> {
        if flags & !(RTLD_LAZY | RTLD_NOW | RTLD_GLOBAL) != 0
            || !matches!(flags & (RTLD_LAZY | RTLD_NOW), RTLD_LAZY | RTLD_NOW)
        {
            return Err(libc::EINVAL);
        }
        let gate = self.enter(thread);
        if !matches!(group.state(), GroupState::Linked | GroupState::Draining) {
            return Err(libc::ECANCELED);
        }
        let global = flags & RTLD_GLOBAL != 0;
        let path = match path {
            Some(path) => Some(self.resolve(path, cwd)?),
            None => None,
        };
        let identity = path.as_ref().map(|path| identity_from_path(path));
        let mut state = self.state.irqsave_lock();
        let existing_handle = if let Some(identity) = &identity {
            state
                .objects()
                .find(|object| object.descriptor.identity() == identity)
                .map(|object| object.handle)
        } else {
            state.base.first().map(|object| object.handle)
        };
        if let Some(handle) = existing_handle {
            let object = state.object_mut(handle).ok_or(libc::EINVAL)?;
            object.opens = object.opens.checked_add(1).ok_or(libc::EOVERFLOW)?;
            let promote: Vec<_> = if global {
                object
                    .lookup
                    .iter()
                    .map(|image| image.identity().clone())
                    .collect()
            } else {
                Vec::new()
            };
            for object in state.objects_mut() {
                if promote.contains(object.descriptor.identity()) {
                    object.global = true;
                }
            }
            return Ok(BlueOsDlPlan {
                handle,
                ..BlueOsDlPlan::empty()
            });
        }
        let path = path.ok_or(libc::EINVAL)?;
        // A fini plan still executing may refer to this identity. Reject
        // recursive reopening of that same closing generation.
        if state.pending.iter().any(|op| match &op.kind {
            OperationKind::Close { batches } => batches.iter().any(|batch| {
                batch
                    .objects
                    .iter()
                    .any(|object| Some(object.descriptor.identity()) == identity.as_ref())
            }),
            _ => false,
        }) {
            return Err(libc::EBUSY);
        }
        state.batches.try_reserve(1).map_err(|_| libc::ENOMEM)?;
        state.pending.try_reserve(1).map_err(|_| libc::ENOMEM)?;
        let existing = state.snapshot();
        drop(state);
        let service = ApplicationService::get().ok_or(libc::ENOSYS)?;
        let PreparedLoad {
            mut batch,
            init,
            system,
        } = service.prepare_runtime_load(group.clone(), self.namespace.clone(), path, existing)?;
        let handle = batch.objects.first().ok_or(libc::ENOEXEC)?.handle;
        batch.objects[0].opens = 1;
        let promote: Vec<_> = if global {
            batch.objects[0]
                .lookup
                .iter()
                .map(|image| image.identity().clone())
                .collect()
        } else {
            Vec::new()
        };
        let id = batch.id;
        let operation = Operation {
            token: token()?,
            handle,
            entries: init,
            error: 0,
            kind: OperationKind::Open { batch: id, system },
        };
        let plan = operation.plan();
        let mut state = self.state.irqsave_lock();
        state.batches.push(batch);
        for object in state.objects_mut() {
            if promote.contains(object.descriptor.identity()) {
                object.global = true;
            }
        }
        state.pending.push(operation);
        drop(state);
        gate.hand_off();
        Ok(plan)
    }

    fn resolve(&self, path: &str, cwd: &str) -> Result<String> {
        let service = ApplicationService::get().ok_or(libc::ENOSYS)?;
        let mut candidates = resolve_dependency_paths(
            &self.namespace,
            ResolveBase::CurrentWorkingDirectory(cwd),
            path,
        );
        if DependencyKind::classify(path) == DependencyKind::PlainName {
            if let Some(entry) = service.runtime_catalog().resolve_name(path.as_bytes()) {
                candidates.push(String::from(entry.path));
            }
        }
        for candidate in candidates {
            if self
                .state
                .irqsave_lock()
                .objects()
                .any(|object| object.descriptor.identity() == &identity_from_path(&candidate))
            {
                return Ok(candidate);
            }
            match crate::vfs::open_path(&candidate, libc::O_RDONLY, 0) {
                Ok(_) => return Ok(candidate),
                Err(error)
                    if error == crate::error::code::ENOENT
                        || error == crate::error::code::ENOTDIR => {}
                Err(_) => return Err(libc::EACCES),
            }
        }
        Err(libc::ENOENT)
    }

    pub(crate) fn symbol(&self, handle: usize, name: &[u8], thread: usize) -> Result<usize> {
        let _gate = self.enter(thread);
        let state = self.state.irqsave_lock();
        if handle == 0 {
            return state
                .objects()
                .filter(|object| object.global)
                .find_map(|object| object.descriptor.lookup_export(name))
                .map(|address| address.get() as usize)
                .ok_or(libc::ENOENT);
        }
        let object = state
            .objects()
            .find(|object| object.handle == handle && object.opens != 0)
            .ok_or(libc::EINVAL)?;
        // dlopen(NULL) searches the live global namespace, including promoted
        // runtime images, rather than only the startup dependency closure.
        if state.base.first().is_some_and(|base| base.handle == handle) {
            return state
                .objects()
                .filter(|object| object.global)
                .find_map(|object| object.descriptor.lookup_export(name))
                .map(|address| address.get() as usize)
                .ok_or(libc::ENOENT);
        }
        object
            .lookup
            .iter()
            .find_map(|image| image.lookup_export(name))
            .map(|address| address.get() as usize)
            .ok_or(libc::ENOENT)
    }

    pub(crate) fn close(&self, handle: usize, thread: usize) -> Result<BlueOsDlPlan> {
        let gate = self.enter(thread);
        let mut state = self.state.irqsave_lock();
        if state.batches.iter().any(|batch| {
            batch.initializing && batch.objects.iter().any(|object| object.handle == handle)
        }) {
            return Err(libc::EBUSY);
        }
        let object = state
            .object_mut(handle)
            .filter(|object| object.opens != 0)
            .ok_or(libc::EINVAL)?;
        object.opens -= 1;
        let result = state.collect();
        if result.is_err() {
            state.object_mut(handle).unwrap().opens += 1;
        }
        let plan = result?;
        drop(state);
        if plan.token != 0 {
            gate.hand_off();
        }
        Ok(plan)
    }

    pub(crate) fn exit(&self, thread: usize) -> Result<BlueOsDlPlan> {
        let gate = self.enter(thread);
        let mut state = self.state.irqsave_lock();
        if !state.pending.is_empty() {
            return Err(libc::EBUSY);
        }
        state.exiting = true;
        let plan = state.collect()?;
        drop(state);
        if plan.token != 0 {
            gate.hand_off();
        }
        Ok(plan)
    }

    pub(crate) fn finish(&self, token: usize, thread: usize) -> Result<BlueOsDlPlan> {
        if self.owner.load(Ordering::Acquire) != thread {
            return Err(libc::EPERM);
        }
        let mut state = self.state.irqsave_lock();
        if token == 0 || state.pending.last().is_none_or(|op| op.token != token) {
            return Err(libc::EINVAL);
        }
        let operation = state.pending.pop().unwrap();
        if state.pending.is_empty() {
            state.pending = Vec::new();
        }
        drop(state);
        // The matching operation already owns one gate level. Release it on
        // every error as well as success, unless a follow-up fini plan takes it.
        let gate = Gate {
            runtime: self,
            armed: true,
        };
        let result = match operation.kind {
            OperationKind::Open { batch, mut system } => {
                let service = ApplicationService::get().ok_or(libc::ENOSYS)?;
                match service.finish_runtime_init(&mut system) {
                    Ok(leases) => {
                        let mut state = self.state.irqsave_lock();
                        let batch = state
                            .batches
                            .iter_mut()
                            .find(|candidate| candidate.id == batch)
                            .ok_or(libc::EINVAL)?;
                        batch.receipt.as_mut().unwrap().attach_system_leases(leases);
                        batch.initializing = false;
                        Ok(BlueOsDlPlan::empty())
                    }
                    Err(error) => {
                        let allocations = service.fail_runtime_init(system);
                        let mut state = self.state.irqsave_lock();
                        let failed = state
                            .batches
                            .iter_mut()
                            .find(|candidate| candidate.id == batch)
                            .ok_or(libc::EINVAL)?;
                        failed
                            .receipt
                            .as_mut()
                            .unwrap()
                            .retain_failed_system_allocations(allocations);
                        failed.initializing = false;
                        failed.fini = core::mem::take(&mut failed.rollback_fini);
                        failed.objects[0].opens -= 1;
                        for object in &mut failed.objects {
                            object.global = false;
                        }
                        let mut plan = state.collect()?;
                        if plan.token == 0 {
                            Err(error)
                        } else {
                            state.pending.last_mut().unwrap().error = error;
                            plan.error = error;
                            Ok(plan)
                        }
                    }
                }
            }
            OperationKind::Close { batches } => {
                drop(batches);
                // A recursive fini may close a provider retained by this
                // operation. Collect it only after these consumers are gone.
                self.state.irqsave_lock().collect()
            }
        };
        if result.as_ref().is_ok_and(|plan| plan.token != 0) {
            gate.hand_off();
        }
        result
    }

    /// Called after all application members retired. Never executes private
    /// destructors on an abnormal exit; backing release runs outside the lock.
    pub(crate) fn abandon(&self) {
        let mut state = self.state.irqsave_lock();
        let pending = core::mem::take(&mut state.pending);
        let batches = core::mem::take(&mut state.batches);
        drop(state);
        drop(pending);
        drop(batches);
    }
}

impl State {
    fn objects(&self) -> impl Iterator<Item = &Object> {
        self.base
            .iter()
            .chain(self.batches.iter().flat_map(|batch| &batch.objects))
    }
    fn objects_mut(&mut self) -> impl Iterator<Item = &mut Object> {
        self.base
            .iter_mut()
            .chain(self.batches.iter_mut().flat_map(|batch| &mut batch.objects))
    }
    fn object_mut(&mut self, handle: usize) -> Option<&mut Object> {
        self.objects_mut().find(|object| object.handle == handle)
    }
    fn snapshot(&self) -> Vec<ExistingImage> {
        self.base
            .iter()
            .map(|object| (object, 0))
            .chain(
                self.batches
                    .iter()
                    .flat_map(|batch| batch.objects.iter().map(move |object| (object, batch.id))),
            )
            .map(|(object, batch)| ExistingImage {
                descriptor: object.descriptor.clone(),
                system: object.system,
                global: object.global,
                batch,
            })
            .collect()
    }

    fn collect(&mut self) -> Result<BlueOsDlPlan> {
        let exit_collect = self.exiting && self.pending.is_empty();
        let mut reachable = Vec::new();
        reachable
            .try_reserve(self.batches.len())
            .map_err(|_| libc::ENOMEM)?;
        for batch in &self.batches {
            if batch.initializing
                || (!exit_collect && batch.objects.iter().any(|object| object.opens != 0))
            {
                reachable.push(batch.id);
            }
        }
        for op in &self.pending {
            if let OperationKind::Close { batches } = &op.kind {
                for batch in batches {
                    for dependency in &batch.dependencies {
                        if !reachable.contains(dependency) {
                            reachable.push(*dependency);
                        }
                    }
                }
            }
        }
        let mut cursor = 0;
        while cursor < reachable.len() {
            if let Some(batch) = self
                .batches
                .iter()
                .find(|batch| batch.id == reachable[cursor])
            {
                for dependency in &batch.dependencies {
                    if !reachable.contains(dependency) {
                        reachable.push(*dependency);
                    }
                }
            }
            cursor += 1;
        }
        let Some(index) = (0..self.batches.len())
            .rev()
            .find(|index| !reachable.contains(&self.batches[*index].id))
        else {
            return Ok(BlueOsDlPlan::empty());
        };
        // Retain older batches in the live namespace while a consumer's fini
        // runs. Its callbacks can dlopen/dlsym dependencies, and may close an
        // explicitly retained handle even during automatic exit finalization.
        let count = self.batches[index].fini.len();
        self.pending.try_reserve(1).map_err(|_| libc::ENOMEM)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(count).map_err(|_| libc::ENOMEM)?;
        let mut removed = Vec::new();
        removed.try_reserve_exact(1).map_err(|_| libc::ENOMEM)?;
        let id = token()?;
        let batch = self.batches.remove(index);
        entries.extend_from_slice(&batch.fini);
        removed.push(batch);
        if self.batches.is_empty() {
            self.batches = Vec::new();
        }
        let operation = Operation {
            token: id,
            handle: 0,
            entries: entries.into_boxed_slice(),
            error: 0,
            kind: OperationKind::Close { batches: removed },
        };
        let plan = operation.plan();
        self.pending.push(operation);
        Ok(plan)
    }
}

fn context_closure(context: &LinkContext, root: usize) -> Vec<Arc<PublishedImageDescriptor>> {
    let mut queue = alloc::vec![root];
    let mut cursor = 0;
    while cursor < queue.len() {
        let requester = queue[cursor];
        for edge in context
            .graph_edges()
            .iter()
            .filter(|edge| edge.requester().get() as usize == requester)
        {
            let id = edge.provider().get() as usize;
            if !queue.contains(&id) {
                queue.push(id);
            }
        }
        cursor += 1;
    }
    queue
        .into_iter()
        .map(|id| context.images()[id].descriptor_handle())
        .collect()
}

/// Runs entirely on the service's link stack. Preparing descriptors, pinned
/// plans and dependency retention must finish before the caller installs it.
pub(crate) fn prepare_load(
    service: &ApplicationService,
    group: &ThreadGroup,
    namespace: &ApplicationNamespace,
    path: &str,
    existing: Vec<ExistingImage>,
) -> Result<PreparedLoad> {
    let plan = NamespaceLoadPlanner::new(
        namespace,
        service.runtime_catalog(),
        blueos_loader::SessionLimits::DEFAULT,
    )
    .plan_shared(path)
    .map_err(load_errno)?;
    let identities: Vec<_> = plan
        .images()
        .iter()
        .map(|image| image.identity().clone())
        .collect();
    let edges: Vec<_> = plan
        .edges()
        .iter()
        .map(|edge| (edge.requester(), edge.provider()))
        .collect();
    let globals = existing
        .iter()
        .filter(|image| image.global)
        .map(|image| {
            if image.system {
                blueos_loader::ImportedImageDescriptor::new(image.descriptor.clone())
            } else {
                blueos_loader::ImportedImageDescriptor::namespace(image.descriptor.clone())
            }
        })
        .collect();
    let imports = existing
        .iter()
        .map(|image| (image.descriptor.clone(), image.system))
        .collect();
    let (product, system) = service
        .runtime_loader()
        .link_shared(plan, namespace.profile(), group, imports, globals)
        .map_err(load_errno)?;
    let mut dependencies = Vec::new();
    for image in &existing {
        if image.batch != 0
            && (identities.contains(image.descriptor.identity())
                || product.relocation_bindings().iter().any(|binding| {
                    binding.provider().is_some_and(|owner| {
                        product.context().images()[owner.get() as usize]
                            .descriptor()
                            .identity()
                            == image.descriptor.identity()
                    })
                }))
            && !dependencies.contains(&image.batch)
        {
            dependencies.push(image.batch);
        }
    }
    let init = product
        .lifecycle_plans()
        .startup()
        .iter()
        .map(|entry| entry.function().get() as usize)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let fini: Box<[usize]> = product
        .lifecycle_plans()
        .group_fini()
        .iter()
        .map(|entry| entry.function().get() as usize)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let rollback_fini = fini
        .iter()
        .copied()
        .chain(
            product
                .lifecycle_plans()
                .system_fini()
                .iter()
                .flat_map(|image| {
                    image
                        .plan()
                        .iter()
                        .map(|entry| entry.function().get() as usize)
                }),
        )
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let descriptors: Vec<_> = product
        .context()
        .images()
        .iter()
        .map(|image| (image.descriptor_handle(), image.ownership()))
        .collect();
    let receipt = product.into_publication();
    let mut batch = Batch {
        id: 0,
        objects: Vec::new(),
        dependencies,
        fini,
        rollback_fini,
        receipt: Some(receipt),
        initializing: true,
    };
    batch.id = token()?;
    // Plan order keeps the runtime root first even though global providers were
    // inserted before its dependencies in the link session.
    for (index, identity) in identities.iter().enumerate() {
        if existing
            .iter()
            .any(|image| image.descriptor.identity() == identity)
        {
            continue;
        }
        let (descriptor, ownership) = descriptors
            .iter()
            .find(|(image, _)| image.identity() == identity)
            .ok_or(libc::ENOEXEC)?;
        let mut queue = alloc::vec![index];
        let mut cursor = 0;
        while cursor < queue.len() {
            let current = queue[cursor];
            for (_, provider) in edges.iter().filter(|(requester, _)| *requester == current) {
                if !queue.contains(provider) {
                    queue.push(*provider);
                }
            }
            cursor += 1;
        }
        let lookup = queue
            .into_iter()
            .map(|id| {
                descriptors
                    .iter()
                    .find(|(image, _)| image.identity() == &identities[id])
                    .map(|(image, _)| image.clone())
                    .or_else(|| {
                        existing
                            .iter()
                            .find(|image| image.descriptor.identity() == &identities[id])
                            .map(|image| image.descriptor.clone())
                    })
                    .ok_or(libc::ENOEXEC)
            })
            .collect::<Result<Vec<_>>>()?;
        batch.objects.push(Object {
            handle: token()?,
            descriptor: descriptor.clone(),
            system: matches!(
                ownership,
                ImageOwnership::SystemCandidate | ImageOwnership::ExternalReady
            ),
            global: false,
            opens: 0,
            lookup,
        });
    }
    Ok(PreparedLoad {
        batch,
        init,
        system,
    })
}

fn load_errno(error: blueos_loader::LoadError) -> i32 {
    log::error!("runtime link failed: {:?}", error);
    if matches!(error.kind(), blueos_loader::LoadErrorKind::OutOfMemory) {
        libc::ENOMEM
    } else {
        libc::ENOEXEC
    }
}
