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

//! Deferred application reaper: release a drained group's resources.
//!
//! [`ApplicationReaper`] is the consuming counterpart to [`ApplicationLoader`]:
//! a cloneable handle onto the shared registry and the shared-flat memory
//! service. Once the exit coordinator has driven a group to `Draining`, all its
//! member threads have left and the fini plan is resolved, the reaper takes the
//! group's publication receipt, releases the private image leases, drops the
//! counted imported DSO leases, and resolves each resulting registry quiescence
//!
//! System instances retain cross-SCC dependency leases. After dropping an
//! application's leases, the reaper resolves zero-user SCCs to a fixed point:
//! cache-pinned groups stay Ready, while unloadable groups remain hidden in
//! `Unloading` through fini and backing release. Dropping one group's outgoing
//! leases can make another group quiescent, hence the bounded retry loop.

use alloc::{boxed::Box, sync::Arc, vec::Vec};

use super::adapters::system_paths::SystemLibraryKey;
use blueos_loader::memory::ImageMemory;

use crate::{
    application::{
        adapters::flat_memory::FlatImageMemory,
        group::{GroupState, ThreadGroup, ThreadGroupError},
        manager::ApplicationManager,
        publication::KernelLinkReceipt,
        registry::{QuiescenceResolution, SystemDsoRegistry},
    },
    thread::{self, Builder, Entry},
};

use crate::thread::deferred;

/// Resource counts produced by one reap operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReapReport {
    /// Number of private (root and session-private) image leases released.
    pub private_images: usize,
    /// Number of counted imported DSO references dropped and resolved.
    pub imported_dsos: usize,
}

/// The bound between two reaper scans: the thread parks on an atomic wait with
/// this timeout, then re-checks every pending group. Member exits and lifecycle
/// transitions are all lock-free observable state, so a short bounded poll is
/// the wait primitive; registration still wakes the thread promptly.
const REAPER_POLL_MILLIS: u64 = 10;

/// A cloneable handle that reaps drained application groups.
#[derive(Clone)]
pub struct ApplicationReaper {
    registry: SystemDsoRegistry,
    memory: FlatImageMemory,
    /// Every group a launch handed over — successfully or failed — waiting to
    /// be reaped once its members left and its fini resolved.
    pending: Arc<spin::Mutex<Vec<ThreadGroup>>>,
}

impl ApplicationReaper {
    /// Build a reaper over the shared registry and shared-flat memory service.
    pub fn new(registry: SystemDsoRegistry, memory: FlatImageMemory) -> Self {
        Self {
            registry,
            memory,
            pending: Arc::new(spin::Mutex::new(Vec::new())),
        }
    }

    /// Hand a launched group to the reaper for eventual resource release.
    /// The group stays watched until its members have exited, its fini has
    /// resolved and its resources were taken; failed launches hand their group
    /// over the same way.
    pub fn register(&self, group: &ThreadGroup) {
        self.pending.lock().push(group.clone());
        deferred::notify();
    }

    /// Spawn the kernel reaper thread. It owns clones of the reaper and the
    /// manager and never returns. The reaper releases resources outside every
    /// registry or manager lock.
    ///
    /// Retirement depends on this thread: it runs the cleanups that release a
    /// retired thread's stack and drop its group membership, so an application
    /// cannot finish exiting until the reaper is scheduled. A spawn that fails
    /// would strand every later cleanup, so it is fatal rather than asserted.
    pub fn spawn(&self, manager: ApplicationManager) {
        let reaper = self.clone();
        let thread = Builder::new(Entry::Closure(Box::new(move || reaper.run(manager)))).build();
        if crate::scheduler::queue_ready_thread(thread::IDLE, thread).is_err() {
            panic!("application reaper thread must queue");
        }
    }

    /// The reaper thread body.
    ///
    /// The order of one pass matters. The generation is read *before* the
    /// queue and the pending groups are inspected, so a cleanup posted or a
    /// group registered mid-pass moves the value the following wait compares
    /// against — it wakes this thread rather than being slept through.
    ///
    /// Posted cleanups run first. Dropping a retired thread's group membership
    /// is part of its cleanup, and a group that still holds a member is not
    /// empty, so no group can be reaped — and no image released — while a
    /// cleanup that still refers to that image is pending.
    fn run(&self, manager: ApplicationManager) -> ! {
        loop {
            let generation = deferred::generation();
            deferred::drain();
            self.scan(&manager);
            // A bounded wait: member exits and lifecycle transitions are plain
            // shared state with no wake plumbing into this thread, so the poll
            // bound is what makes the reaper eventually observe them.
            let _ = crate::sync::atomic_wait(
                deferred::wait_address(),
                generation,
                crate::time::Tick::from_millis(REAPER_POLL_MILLIS),
            );
        }
    }

    /// One pass over every pending group.
    fn scan(&self, manager: &ApplicationManager) {
        // Release batches abandoned before ownership was attached to a running
        // group. Group-owned initialization failures stay in that group's
        // receipt and are released only after all of its threads have exited.
        let mut memory = self.memory.clone();
        for allocation in self.registry.drain_failed_backings() {
            memory.release_committed(allocation);
        }
        // Detach one pass under the short queue lock. Reaping runs application
        // destructors, which may launch/register another group on this reaper.
        let mut pending = core::mem::take(&mut *self.pending.lock());
        let mut index = 0;
        while index < pending.len() {
            if !self.try_reap(&pending[index]) {
                index += 1;
                continue;
            }
            let group = pending.swap_remove(index);
            let handle = group.handle();
            // Drop the reaper's reference before the manager publishes Vacant,
            // so the pending set cannot keep member storage alive after
            // contains(handle) becomes false.
            drop(group);
            if let Some(handle) = handle {
                let _ = manager.finish(handle);
                let _ = manager.release(handle);
            }
        }
        // Registrations made during callbacks remain queued for the next pass;
        // append the survivors without replacing those new registrations.
        let mut queued = self.pending.lock();
        if queued.is_empty() {
            // Reuse the detached vector's capacity on the usual quiet pass.
            *queued = pending;
        } else {
            queued.append(&mut pending);
        }
    }

    /// Advance one group towards reaping and return `true` once it is fully
    /// reaped (and may leave the pending set). Covers the terminal
    /// shapes:
    ///
    /// - `New`: the launch failed before installing a product; nothing to
    ///   release, only the manager's `Failed` slot to recycle.
    /// - `Linked` with no members: the main thread died without reporting
    ///   exit; force the abnormal drain with a skipped fini and fall through.
    /// - `Draining` with no members and a pending fini: the coordinator died
    ///   mid-atexit; skip the fini and fall through.
    /// - `Draining` with no members and a resolved fini: take the resources,
    ///   release the private images and drop the imported leases. The scan
    ///   then drops the group reference and recycles the manager slot.
    fn try_reap(&self, group: &ThreadGroup) -> bool {
        match group.state() {
            GroupState::Reaped => return true,
            GroupState::New => {
                // No product was installed; scan only needs to drop the group
                // and recycle the manager's Failed slot.
                return true;
            }
            GroupState::Linked => {
                if !group.is_empty() {
                    return false;
                }
                // Main thread died without ApplicationBeginExit: abnormal
                // drain, destructors are skipped with a recorded reason
                let _ = group.begin_exit();
                let _ = group.skip_fini();
            }
            GroupState::Draining => {
                if !group.is_empty() {
                    return false;
                }
                if !group.fini_resolved() {
                    // Coordinator died between BeginExit and FinishExit:
                    // skip the destructor plan and fall through.
                    let _ = group.skip_fini();
                }
            }
        }
        match self.reap(group) {
            Ok(report) => {
                // The checker asserts the private-image
                // count and the imported-DSO count of every reap.
                if let Some(handle) = group.handle() {
                    log::info!(
                        "APP_REAP handle={}:{} private_images={} imported_dsos={}",
                        handle.slot,
                        handle.generation,
                        report.private_images,
                        report.imported_dsos
                    );
                }
            }
            Err(_) => {
                // Not ready after all (a member raced back in); retry next
                // scan.
                return false;
            }
        }
        true
    }

    /// Take the group's resources and release every private image exactly once,
    /// resolving the quiescence of every imported DSO this application held.
    /// Returns [`ThreadGroupError`] when the group is not yet ready to
    /// reap (still draining, members remain, fini pending, or already reaped).
    pub fn reap(&self, group: &ThreadGroup) -> Result<ReapReport, ThreadGroupError> {
        let (receipt, start_storage) = group.take_resources_for_reap()?;
        if let Some(runtime) = group.take_runtime() {
            runtime.abandon();
            drop(runtime);
        }
        // The start storage holds no leases; dropping it releases the pinned
        // argv/envp/auxv/init/fini backing once no thread can read it.
        drop(start_storage);
        Ok(self.release_receipt(receipt))
    }

    /// Release a runtime link after the application's destructor plan finished.
    /// No group, loader or registry lock may be held while this runs.
    pub(crate) fn release_receipt(&self, receipt: KernelLinkReceipt) -> ReapReport {
        let (private, failed_system, system_leases) = receipt.into_parts();

        // `FlatImageMemory` is a handle onto a shared service; `release_committed`
        // needs `&mut self`, so release through a per-call clone like the loader's
        // link session does (`let mut memory = self.memory.clone()`).
        let mut memory = self.memory.clone();
        let private_images = private.len();
        for lease in private {
            memory.release_committed(lease);
        }
        for lease in failed_system {
            memory.release_committed(lease);
        }

        let imported_dsos = system_leases.len();
        let mut quiescence: Vec<SystemLibraryKey> = Vec::new();
        for lease in system_leases {
            let key = lease.key().clone();
            quiescence.push(key);
            drop(lease);
        }

        loop {
            let mut made_progress = false;
            let mut request = 0;
            while request < quiescence.len() {
                let resolution = self.registry.resolve_quiescence(&quiescence[request]);
                match resolution {
                    Some(QuiescenceResolution::KeptCached) => {
                        quiescence.swap_remove(request);
                        made_progress = true;
                    }
                    Some(QuiescenceResolution::Unloaded(mut batch)) => {
                        let backings = batch.take_backings();
                        let mut unloaded_names = Vec::new();
                        // Every SCC member and outgoing provider must stay
                        // mapped until all destructors in the component finish.
                        // A later member's fini can call an earlier member.
                        for backing in &backings {
                            for entry in backing.fini_plan.iter() {
                                // SAFETY: the fini targets were validated against the
                                // owner's executable region at plan build time, and the
                                // allocation is still mapped — it is released only
                                // after every destructor completed.
                                unsafe {
                                    let function: extern "C" fn() = core::mem::transmute(*entry);
                                    function();
                                }
                            }
                            log::info!(
                                "DSO_FINI path={}",
                                core::str::from_utf8(backing.key.as_bytes())
                                    .unwrap_or("<non-utf8>")
                            );
                        }
                        for backing in backings {
                            let crate::application::registry::SystemUnloadBacking {
                                key,
                                allocation,
                                fini_plan: _,
                                dependencies,
                            } = backing;
                            memory.release_committed(allocation);
                            log::info!(
                                "DSO_UNLOAD path={}",
                                core::str::from_utf8(key.as_bytes()).unwrap_or("<non-utf8>")
                            );
                            // Actual global providers may not occur in this
                            // application's declared closure. Queue them when
                            // releasing retention leases so they are reaped too.
                            for dependency in dependencies {
                                if !quiescence.contains(dependency.key()) {
                                    quiescence.push(dependency.key().clone());
                                }
                                drop(dependency);
                            }
                            unloaded_names.push(key);
                        }
                        let finished = self.registry.finish_unload(batch);
                        debug_assert!(finished.is_ok());
                        if finished.is_err() {
                            log::error!("system DSO unload completion rejected");
                        }
                        quiescence.retain(|key| !unloaded_names.contains(key));
                        made_progress = true;
                    }
                    None => request += 1,
                }
            }
            if quiescence.is_empty() || !made_progress {
                break;
            }
        }

        ReapReport {
            private_images,
            imported_dsos,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::{
        registry::AcquireBatchOutcome,
        start_storage::ApplicationStartStorage,
        test_support::{load_image, publish_candidates, with_loader_stack},
    };
    use blueos_loader::memory::{AllocationOffset, ImageAllocation};
    use blueos_test_macro::test;
    use spin::Mutex;

    struct FiniState {
        memory: FlatImageMemory,
        allocations: Vec<ImageAllocation>,
        order: Vec<usize>,
        registration: Option<(ApplicationReaper, ThreadGroup)>,
    }
    static FINI_STATE: Mutex<Option<FiniState>> = Mutex::new(None);

    fn mapped(memory: &FlatImageMemory, allocation: &ImageAllocation) -> bool {
        memory
            .image_span(allocation, AllocationOffset::new(0), 1)
            .is_ok()
    }

    extern "C" fn first_fini() {
        record_fini(1);
    }
    extern "C" fn second_fini() {
        record_fini(2);
    }
    fn record_fini(index: usize) {
        let mut state = FINI_STATE.lock();
        let state = state.as_mut().unwrap();
        for allocation in &state.allocations {
            assert!(
                mapped(&state.memory, allocation),
                "all SCC members must survive every fini"
            );
        }
        state.order.push(index);
        if let Some((reaper, group)) = state.registration.take() {
            // Fail promptly on a lock regression instead of spinning forever
            // inside register, then exercise the actual callback registration.
            assert!(
                reaper.pending.try_lock().is_some(),
                "pending lock held during fini"
            );
            reaper.register(&group);
        }
    }

    #[test]
    fn shared_provider_survives_its_first_importer_and_reaps_after_the_consumer() {
        with_loader_stack(shared_provider_lifetime);
    }

    fn shared_provider_lifetime() {
        let registry = SystemDsoRegistry::new();
        let memory = FlatImageMemory::new();
        let reaper = ApplicationReaper::new(registry.clone(), memory.clone());
        let provider = b"/system/lib/provider.so".as_slice();
        let consumer = b"/system/lib/consumer.so".as_slice();
        let (provider_leases, provider_allocations) = publish_candidates(
            &registry,
            &memory,
            &[provider],
            &[],
            &[Vec::new()],
            &[Vec::new()],
        );
        let (consumer_leases, consumer_allocations) = publish_candidates(
            &registry,
            &memory,
            &[consumer],
            &[],
            &[Vec::new()],
            &[alloc::vec![SystemLibraryKey::from_bytes(provider).unwrap()]],
        );
        let mut first_receipt = load_image(&memory, b"first", false).into_receipt();
        first_receipt.attach_system_leases(provider_leases);
        reaper.release_receipt(first_receipt);
        assert!(
            mapped(&memory, &provider_allocations[0]),
            "consumer retains provider after its original importer exits"
        );

        // This receipt contains no direct provider lease. Dropping the
        // consumer's outgoing lease must discover and reap the provider.
        let mut last_receipt = load_image(&memory, b"last", false).into_receipt();
        last_receipt.attach_system_leases(consumer_leases);
        reaper.release_receipt(last_receipt);
        assert!(!mapped(&memory, &consumer_allocations[0]));
        assert!(!mapped(&memory, &provider_allocations[0]));
        let keys = [
            SystemLibraryKey::from_bytes(provider).unwrap(),
            SystemLibraryKey::from_bytes(consumer).unwrap(),
        ];
        let AcquireBatchOutcome::Acquired(batch) = registry.acquire_batch(&keys) else {
            panic!("providers must be vacant after unload")
        };
        assert_eq!(batch.loads.len(), 2);
        assert!(batch.imports.is_empty());
    }

    #[test]
    fn scc_runs_fini_in_loader_order_before_releasing_any_member() {
        with_loader_stack(scc_fini_order);
    }

    fn scc_fini_order() {
        let registry = SystemDsoRegistry::new();
        let memory = FlatImageMemory::new();
        let reaper = ApplicationReaper::new(registry.clone(), memory.clone());
        let a = b"/system/lib/a.so".as_slice();
        let b = b"/system/lib/b.so".as_slice();
        let (leases, allocations) = publish_candidates(
            &registry,
            &memory,
            &[a, b],
            &[b, a],
            &[
                alloc::vec![second_fini as usize],
                alloc::vec![first_fini as usize],
            ],
            &[Vec::new(), Vec::new()],
        );
        *FINI_STATE.lock() = Some(FiniState {
            memory: memory.clone(),
            allocations: allocations.clone(),
            order: Vec::new(),
            registration: None,
        });
        let mut receipt = load_image(&memory, b"scc-owner", false).into_receipt();
        receipt.attach_system_leases(leases);
        reaper.release_receipt(receipt);
        let state = FINI_STATE.lock().take().unwrap();
        assert_eq!(state.order, [1, 2]);
        for allocation in allocations {
            assert!(!mapped(&memory, &allocation));
        }
    }

    #[test]
    fn scan_allows_fini_to_register_a_group_and_preserves_pending_survivors() {
        with_loader_stack(scan_registration);
    }

    fn scan_registration() {
        let registry = SystemDsoRegistry::new();
        let memory = FlatImageMemory::new();
        let reaper = ApplicationReaper::new(registry.clone(), memory.clone());
        let manager = ApplicationManager::new(registry.clone());
        let (leases, allocations) = publish_candidates(
            &registry,
            &memory,
            &[b"/system/lib/reentrant.so"],
            &[],
            &[alloc::vec![first_fini as usize]],
            &[Vec::new()],
        );
        let group = ThreadGroup::new(&registry);
        let mut product = load_image(&memory, b"reaped-group", false);
        let storage =
            ApplicationStartStorage::build(b"reaped-group", &[], &[], &product, 1).unwrap();
        product.receipt_mut().attach_system_leases(leases);
        group
            .install_resources(product.into_receipt(), storage)
            .unwrap();
        let survivor = ThreadGroup::new(&registry);
        let member = Builder::new(Entry::C(unreachable_thread)).build();
        survivor.add_member(member.clone()).unwrap();
        // A Linked group with a live member survives this pass.
        let product = load_image(&memory, b"survivor", false);
        let storage = ApplicationStartStorage::build(b"survivor", &[], &[], &product, 1).unwrap();
        survivor
            .install_resources(product.into_receipt(), storage)
            .unwrap();
        let registered = ThreadGroup::new(&registry);
        *FINI_STATE.lock() = Some(FiniState {
            memory: memory.clone(),
            allocations,
            order: Vec::new(),
            registration: Some((reaper.clone(), registered)),
        });
        reaper.register(&survivor);
        reaper.register(&group);
        reaper.scan(&manager);
        assert_eq!(group.state(), GroupState::Reaped);
        let pending = reaper.pending.lock();
        assert_eq!(
            pending.len(),
            2,
            "callback registration and survivor both remain queued"
        );
        assert!(pending.iter().any(|group| group.state() == GroupState::New));
        assert!(pending
            .iter()
            .any(|group| group.state() == GroupState::Linked));
        drop(pending);
        assert_eq!(FINI_STATE.lock().take().unwrap().order, [1]);
        survivor
            .remove_member(crate::thread::Thread::id(&member))
            .unwrap();
        drop(member);
        reaper.scan(&manager);
        assert!(reaper.pending.lock().is_empty());
    }

    extern "C" fn unreachable_thread() {
        unreachable!("never scheduled")
    }
}
