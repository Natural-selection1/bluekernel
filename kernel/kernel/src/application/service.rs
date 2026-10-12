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

//! Assembled application control plane.
//!
//! [`ApplicationService`] is the single place where the dynamic application
//! stack is wired together: one [`ApplicationManager`], one
//! [`ApplicationLoader`], one [`SystemDsoRegistry`], one
//! [`FlatImageMemory`] service and one [`ApplicationReaper`], over a fixed
//! system library catalog. Boot bootstrap and the
//! `ApplicationLaunch` syscall both reach it through the same singleton and
//! call [`ApplicationService::spawn`]; there is no boot fast path that calls
//! a loader directly.
//!
//! `spawn` uses the manager's `prepare` closure to open the
//! root, prepare and publish the link, pin the start storage, install the product,
//! and start the main thread at the relocated entry after registering it with
//! the group. Every failure before the install drops the armed
//! link session and cancels the registry permits; a failure after the
//! install moves the group to draining with a skipped fini so the deferred
//! reaper releases the installed product.

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Once;

use blueos_header::application::BlueOsStringView;
use blueos_loader::memory::ImageProtectionMemory;

use crate::{
    application::{
        adapters::{flat_memory::FlatImageMemory, system_paths::SystemLibraryPaths},
        group::ThreadGroup,
        loader::ApplicationLoader,
        manager::{
            ApplicationHandle, ApplicationLaunchError, ApplicationManager, OwnedLaunchRequest,
        },
        namespace::ApplicationNamespace,
        reaper::ApplicationReaper,
        registry::SystemDsoRegistry,
        start_storage::ApplicationStartStorage,
    },
    scheduler,
    sync::SpinLock,
    thread::{self, Builder, Entry, GlobalQueueVisitor},
    time::Tick,
};

/// Stack for the thread that performs one launch's link.
///
/// The loader's work follows the size of the dependency closure, so it
/// must not be inherited from whichever thread called `spawn` — at boot that is
/// the shell's main thread, and in the QEMU tests it is the test's main thread.
/// Owning the stack here turns "deep enough" into a decision that this constant
/// records, and keeps the application-facing thread stacks budgeted for
/// application work. Sized against the largest closure in the test corpus
/// (a root plus six private DSOs and one system DSO).
const LINK_STACK_SIZE: usize = 64 * 1024;

/// Completion hand-off between a launch caller and its link worker.
///
/// The worker stores its outcome and then bumps `epoch`; the caller parks on
/// `epoch` and reads the outcome once it moves. A `Semaphore` would be the
/// obvious primitive but it is `!Sync` (its counter is a `Cell`), and this
/// value has to cross the thread boundary.
struct LinkHandoff {
    /// Zero until the worker finishes, then one. Never reset.
    epoch: AtomicUsize,
    outcome: SpinLock<Option<Result<(), ApplicationLaunchError>>>,
}

struct RuntimeLinkHandoff {
    epoch: AtomicUsize,
    outcome: SpinLock<Option<Result<super::dynamic::PreparedLoad, i32>>>,
}

impl LinkHandoff {
    fn new() -> Self {
        Self {
            epoch: AtomicUsize::new(0),
            outcome: SpinLock::new(None),
        }
    }
}

/// The assembled application control plane.
pub struct ApplicationService {
    manager: ApplicationManager,
    loader: ApplicationLoader,
    reaper: ApplicationReaper,
}

static APPLICATION_SERVICE: Once<ApplicationService> = Once::new();

impl ApplicationService {
    /// Assemble the process-wide service over a fixed system library catalog.
    /// Idempotent: later calls return the existing singleton.
    pub(crate) fn init(catalog: &'static SystemLibraryPaths) -> &'static ApplicationService {
        APPLICATION_SERVICE.call_once(|| {
            let memory = FlatImageMemory::new();
            let registry = SystemDsoRegistry::new();
            let loader = ApplicationLoader::new(catalog, registry.clone(), memory.clone());
            let reaper = ApplicationReaper::new(registry.clone(), memory);
            let manager = ApplicationManager::new(registry);
            // The deferred reaper thread owns clones of the reaper and the
            // manager and releases drained groups outside every manager lock
            reaper.spawn(manager.clone());
            Self {
                manager,
                loader,
                reaper,
            }
        })
    }

    /// The singleton, once initialized.
    pub fn get() -> Option<&'static ApplicationService> {
        APPLICATION_SERVICE.get()
    }

    /// The application manager.
    pub fn manager(&self) -> &ApplicationManager {
        &self.manager
    }

    pub(crate) fn runtime_catalog(&self) -> &'static SystemLibraryPaths {
        self.loader.catalog()
    }
    pub(crate) fn runtime_loader(&self) -> &ApplicationLoader {
        &self.loader
    }
    pub(crate) fn release_runtime_receipt(&self, receipt: super::publication::KernelLinkReceipt) {
        self.reaper.release_receipt(receipt);
    }
    pub(crate) fn finish_runtime_init(
        &self,
        batch: &mut super::registry::SystemInitBatch,
    ) -> Result<Vec<super::registry::SystemDsoLease>, i32> {
        self.loader
            .registry()
            .try_finish_initialization_batch(batch)
            .map_err(|_| libc::ENOEXEC)
    }

    pub(crate) fn fail_runtime_init(
        &self,
        batch: super::registry::SystemInitBatch,
    ) -> Vec<blueos_loader::memory::AllocationLease> {
        self.loader.registry().fail_initialization_batch(batch)
    }

    pub(crate) fn prepare_runtime_load(
        &'static self,
        group: ThreadGroup,
        namespace: ApplicationNamespace,
        path: alloc::string::String,
        existing: Vec<super::dynamic::ExistingImage>,
    ) -> Result<super::dynamic::PreparedLoad, i32> {
        let handoff = Arc::new(RuntimeLinkHandoff {
            epoch: AtomicUsize::new(0),
            outcome: SpinLock::new(None),
        });
        let worker = handoff.clone();
        thread::spawn_with_stack(LINK_STACK_SIZE, move || {
            let result = super::dynamic::prepare_load(self, &group, &namespace, &path, existing);
            *worker.outcome.irqsave_lock() = Some(result);
            worker.epoch.store(1, Ordering::Release);
            let _ = crate::sync::atomic_wake(&worker.epoch, usize::MAX);
        })
        .ok_or(libc::ENOMEM)?;
        while handoff.epoch.load(Ordering::Acquire) == 0 {
            let _ = crate::sync::atomic_wait(&handoff.epoch, 0, Tick::MAX);
        }
        let result = handoff
            .outcome
            .irqsave_lock()
            .take()
            .expect("runtime link worker published its result");
        result
    }

    /// Accept the application's init completion: first advance
    /// the pending system batch `Initializing → Ready` and mint the first
    /// group's leases, then move the manager's public state to `Running`.
    /// Only the validated `ApplicationInitComplete` syscall path calls this.
    pub fn complete_init(
        &self,
        group: &ThreadGroup,
        handle: ApplicationHandle,
    ) -> Result<(), ApplicationLaunchError> {
        if let Some(batch) = group.take_pending_system_batch() {
            let leases = self
                .loader
                .registry()
                .finish_initialization_batch(batch)
                .map_err(|_| ApplicationLaunchError::PrepareFailed)?;
            group
                .attach_system_leases(leases)
                .map_err(|_| ApplicationLaunchError::PrepareFailed)?;
        }
        self.manager.complete_init(handle)
    }

    /// Launch a dynamic application: link it against the system catalog,
    /// pin its start storage, install the product into a fresh thread group
    /// and start its main thread at the relocated entry.
    ///
    /// `argv`/`envp` are the owned, already-validated strings the launch
    /// syscall copied in; the returned handle stays `Loading` until the
    /// application reports `ApplicationInitComplete`.
    pub fn spawn(
        &self,
        path: &str,
        argv: Vec<Vec<u8>>,
        envp: Vec<Vec<u8>>,
    ) -> Result<ApplicationHandle, ApplicationLaunchError> {
        let launch_pwd = crate::vfs::get_working_dir().get_full_path();
        let namespace = ApplicationNamespace::from_launch_path(
            path,
            &launch_pwd,
            crate::application::board_dynamic_profile(),
        )
        .ok_or(ApplicationLaunchError::PrepareFailed)?;
        let identity = namespace.root_path().as_bytes().to_vec();
        // The namespace is moved into the link worker below; keep the path for
        // the launch record.
        let launch_path = alloc::string::String::from(namespace.root_path());
        // The link runs on a thread of its own, so the closure handed to the
        // manager has to own everything it captures. The service is a `Once`
        // singleton, so re-fetching it here yields the `'static` handle the
        // worker thread needs.
        let service = ApplicationService::get().ok_or(ApplicationLaunchError::PrepareFailed)?;
        let (result, group) = self
            .manager
            .launch_with_group(OwnedLaunchRequest::new(identity), move |group| {
                service.link_on_own_stack(group.clone(), namespace, argv, envp)
            });
        // Either way the group now belongs to the deferred reaper: a live
        // group is released after its members left and its fini resolved, a
        // failed launch's group (nothing installed, or installed-then-drained)
        // is recycled together with its `Failed` slot.
        self.reaper.register(&group);
        if let Ok(handle) = result {
            // Record the launch so the shell and QEMU checker can correlate
            // applications, DSO generations and reaps.
            log::info!(
                "APP_LAUNCHED handle={}:{} path={}",
                handle.slot,
                handle.generation,
                launch_path
            );
        }
        result
    }

    /// Run [`prepare`](Self::prepare) on a thread whose stack is sized for the
    /// link, and hand its result back to the caller.
    ///
    /// The caller blocks here, and holds no lock while it does: `launch` runs
    /// this closure outside the manager's table lock, so there is no cycle
    /// between the waiting caller and the worker.
    ///
    /// The worker is a plain kernel thread and is deliberately *not* added to
    /// the application's execution set: it is not an application member, and
    /// adding it would corrupt the exit coordinator's member count.
    fn link_on_own_stack(
        &'static self,
        group: ThreadGroup,
        namespace: ApplicationNamespace,
        argv: Vec<Vec<u8>>,
        envp: Vec<Vec<u8>>,
    ) -> Result<(), ApplicationLaunchError> {
        let handoff = Arc::new(LinkHandoff::new());
        let worker = handoff.clone();
        thread::spawn_with_stack(LINK_STACK_SIZE, move || {
            let result = self.prepare(&group, &namespace, &argv, &envp);
            *worker.outcome.irqsave_lock() = Some(result);
            // Publish the outcome before waking, so a caller that observes the
            // bump is guaranteed to observe the value.
            worker.epoch.fetch_add(1, Ordering::Release);
            let _ = crate::sync::atomic_wake(&worker.epoch, usize::MAX);
        })
        .ok_or(ApplicationLaunchError::PrepareFailed)?;

        while handoff.epoch.load(Ordering::Acquire) == 0 {
            // A spurious return only re-reads the epoch; the worker bumps it
            // exactly once and never resets it.
            let _ = crate::sync::atomic_wait(&handoff.epoch, 0, Tick::MAX);
        }
        let mut outcome = handoff.outcome.irqsave_lock();
        outcome
            .take()
            .expect("the worker stores its outcome before bumping the epoch")
    }

    /// The manager's slow prepare closure: VFS open, link preparation, start
    /// storage and main-thread creation all run outside the manager's table
    /// lock.
    fn prepare(
        &self,
        group: &ThreadGroup,
        namespace: &ApplicationNamespace,
        argv: &[Vec<u8>],
        envp: &[Vec<u8>],
    ) -> Result<(), ApplicationLaunchError> {
        let argv_views: Vec<BlueOsStringView> = argv
            .iter()
            .map(|string| BlueOsStringView {
                data: string.as_ptr(),
                len: string.len(),
            })
            .collect();
        let envp_views: Vec<BlueOsStringView> = envp
            .iter()
            .map(|string| BlueOsStringView {
                data: string.as_ptr(),
                len: string.len(),
            })
            .collect();

        let root_path = namespace.root_path();
        let product = self
            .loader
            .link(namespace, group)
            .map_err(|error| prepare_failed("link application", &error))?;

        let granule = self.loader.memory().protection_capabilities().granule();
        let storage = ApplicationStartStorage::build(
            root_path.as_bytes(),
            &argv_views,
            &envp_views,
            &product,
            granule,
        )
        .map_err(|_| ApplicationLaunchError::PrepareFailed)?;

        // The storage heap allocations never move; the pointer stays valid
        // after the install moved the storage into the group.
        let start_info = storage.start_info_ptr();
        let entry = product
            .entry()
            .ok_or(ApplicationLaunchError::PrepareFailed)?
            .get() as usize;
        let runtime = super::dynamic::RuntimeNamespace::new(namespace.clone(), &product)
            .map_err(|_| ApplicationLaunchError::PrepareFailed)?;
        group.install_runtime(runtime);
        let receipt = product.into_receipt();
        group
            .install_resources(receipt, storage)
            .map_err(|_| ApplicationLaunchError::PrepareFailed)?;

        let stack =
            thread::Stack::from_size(blueos_kconfig::CONFIG_MAIN_THREAD_STACK_SIZE as usize)
                .ok_or(ApplicationLaunchError::PrepareFailed)?;
        let mut main = Builder::new(Entry::Raw(entry, start_info as *mut core::ffi::c_void))
            .set_stack(stack)
            .build();
        if group.add_member(main.clone()).is_err() {
            let _ = GlobalQueueVisitor::remove(&mut main);
            // The product is installed but the main thread could not join:
            // move the group to draining with a skipped fini so the deferred
            // reaper releases the installed resources (abnormal path).
            let _ = group.begin_exit();
            let _ = group.skip_fini();
            return Err(ApplicationLaunchError::PrepareFailed);
        }
        let main_id = thread::Thread::id(&main);
        let membership = group.membership();
        main.lock().set_cleanup(Entry::Closure(Box::new(move || {
            if let Some(group) = membership.upgrade() {
                let _ = group.remove_member(main_id);
            }
        })));
        let queued = scheduler::queue_ready_thread(thread::IDLE, main.clone());
        if queued.is_err() {
            let _ = group.remove_member(main_id);
            let _ = GlobalQueueVisitor::remove(&mut main);
            let _ = group.begin_exit();
            let _ = group.skip_fini();
            return Err(ApplicationLaunchError::PrepareFailed);
        }
        Ok(())
    }
}

fn prepare_failed(step: &str, error: &blueos_loader::LoadError) -> ApplicationLaunchError {
    log::error!("application prepare: {step} failed: {:?}", error);
    ApplicationLaunchError::PrepareFailed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::{
        adapters::system_paths::SystemLibraryKey,
        registry::SystemSnapshotOutcome,
        test_support::{install_elf, lifecycle_elf, remove_elf, with_loader_stack},
    };
    use blueos_header::application::BlueOsApplicationStartInfo;
    use blueos_test_macro::test;
    use spin::Mutex;

    static PARENT_STARTED: AtomicUsize = AtomicUsize::new(0);
    static CHILD_STARTED: AtomicUsize = AtomicUsize::new(0);
    static PARENT_RELEASE: AtomicUsize = AtomicUsize::new(0);
    static CHILD_RELEASE: AtomicUsize = AtomicUsize::new(0);
    static FINI_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FINI_THREAD: AtomicUsize = AtomicUsize::new(0);
    static CHILD_HANDLE: Mutex<Option<ApplicationHandle>> = Mutex::new(None);

    extern "C" fn parent_entry(info: *const BlueOsApplicationStartInfo) {
        run_app(info, &PARENT_STARTED, &PARENT_RELEASE);
    }
    extern "C" fn child_entry(info: *const BlueOsApplicationStartInfo) {
        run_app(info, &CHILD_STARTED, &CHILD_RELEASE);
    }
    fn run_app(
        info: *const BlueOsApplicationStartInfo,
        started: &AtomicUsize,
        release: &AtomicUsize,
    ) {
        let service = ApplicationService::get().unwrap();
        let id = thread::Thread::id(&scheduler::current_thread());
        let group = service
            .manager
            .group_for_thread(id)
            .expect("spawned entry belongs to its group");
        let handle = group.handle().unwrap();
        // Execute the start plan and report normal init/exit just as the
        // dynamic startup runtime does, while keeping an explicit test gate.
        let info = unsafe { &*info };
        assert!(info.abi_version != 0);
        for index in 0..info.init_plan.count {
            let target = unsafe { *info.init_plan.entries.add(index) };
            let init: extern "C" fn() = unsafe { core::mem::transmute(target) };
            init();
        }
        service.complete_init(&group, handle).unwrap();
        started.fetch_add(1, Ordering::SeqCst);
        while release.load(Ordering::Acquire) == 0 {
            let _ = crate::sync::atomic_wait(release, 0, Tick::from_millis(50));
        }
        service.manager.begin_exit(handle).unwrap();
        group.begin_exit().unwrap();
        assert_eq!(info.fini_plan.count, 0);
        group.finish_fini().unwrap();
        // A raw application entry has no return trampoline. Drop the local
        // group reference before retiring, so deferred cleanup can reap it.
        drop(group);
        scheduler::retire_me();
    }

    extern "C" fn launch_child_from_fini() {
        let service = ApplicationService::get().unwrap();
        FINI_THREAD.store(
            thread::Thread::id(&scheduler::current_thread()),
            Ordering::SeqCst,
        );
        let path = "/apps/lifecycle/nested.elf";
        let child = service
            .spawn(path, alloc::vec![path.as_bytes().to_vec()], Vec::new())
            .expect("system destructor launches an application");
        *CHILD_HANDLE.lock() = Some(child);
        FINI_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    fn wait_until(mut condition: impl FnMut() -> bool, reason: &str) {
        let deadline = crate::time::now() + core::time::Duration::from_secs(10);
        while !condition() {
            assert!(crate::time::now() < deadline, "{reason}");
            let _ = crate::sync::atomic_wait(
                &FINI_CALLS,
                FINI_CALLS.load(Ordering::Acquire),
                Tick::from_millis(10),
            );
        }
    }

    #[test]
    fn system_destructor_spawns_an_application_and_reaper_keeps_both_children() {
        with_loader_stack(|| {
            for atom in [
                &PARENT_STARTED,
                &CHILD_STARTED,
                &PARENT_RELEASE,
                &CHILD_RELEASE,
                &FINI_CALLS,
                &FINI_THREAD,
            ] {
                atom.store(0, Ordering::SeqCst);
            }
            *CHILD_HANDLE.lock() = None;
            let service = crate::application::runtime::init();
            // Use the existing unloadable catalog entry. Only this test's
            // tmpfs contains the tiny callback ELF; no production policy changes.
            let library = service
                .runtime_catalog()
                .resolve_name(b"libscope_sys.so")
                .unwrap();
            assert!(!library.keep_cached);
            install_elf(
                library.path,
                &lifecycle_elf(true, &[], None, Some(launch_child_from_fini as usize), None),
            );
            install_elf(
                "/apps/lifecycle/parent.elf",
                &lifecycle_elf(
                    false,
                    &[b"libscope_sys.so"],
                    None,
                    None,
                    Some(parent_entry as usize),
                ),
            );
            let child_elf = lifecycle_elf(false, &[], None, None, Some(child_entry as usize));
            install_elf("/apps/lifecycle/survivor.elf", &child_elf);
            install_elf("/apps/lifecycle/nested.elf", &child_elf);
            let survivor = service
                .spawn("/apps/lifecycle/survivor.elf", Vec::new(), Vec::new())
                .unwrap();
            wait_until(
                || CHILD_STARTED.load(Ordering::Acquire) == 1,
                "survivor entry did not run",
            );
            let parent = service
                .spawn("/apps/lifecycle/parent.elf", Vec::new(), Vec::new())
                .unwrap();
            wait_until(
                || PARENT_STARTED.load(Ordering::Acquire) == 1,
                "parent entry did not run",
            );
            PARENT_RELEASE.store(1, Ordering::Release);
            let _ = crate::sync::atomic_wake(&PARENT_RELEASE, usize::MAX);
            wait_until(
                || FINI_CALLS.load(Ordering::Acquire) == 1,
                "destructor spawn blocked, possibly under the reaper pending lock",
            );
            wait_until(
                || CHILD_STARTED.load(Ordering::Acquire) == 2,
                "application spawned by destructor did not enter",
            );
            wait_until(
                || !service.manager.contains(parent),
                "parent slot was not recycled after its destructor",
            );
            let child = CHILD_HANDLE.lock().unwrap();
            assert!(service.manager.contains(survivor));
            assert!(service.manager.contains(child));
            assert_ne!(
                FINI_THREAD.load(Ordering::Acquire),
                thread::Thread::id(&scheduler::current_thread()),
                "system fini must run on the deferred reaper"
            );
            assert!(matches!(
                service
                    .loader
                    .registry()
                    .snapshot(SystemLibraryKey::from_bytes(library.path.as_bytes()).unwrap())
                    .unwrap(),
                SystemSnapshotOutcome::Vacant
            ));

            CHILD_RELEASE.store(1, Ordering::Release);
            let _ = crate::sync::atomic_wake(&CHILD_RELEASE, usize::MAX);
            wait_until(
                || !service.manager.contains(child),
                "reaper lost the group registered during fini",
            );
            wait_until(
                || !service.manager.contains(survivor),
                "reaper lost the survivor from its detached pass",
            );
            assert_eq!(FINI_CALLS.load(Ordering::Acquire), 1);
            for path in [
                library.path,
                "/apps/lifecycle/parent.elf",
                "/apps/lifecycle/survivor.elf",
                "/apps/lifecycle/nested.elf",
            ] {
                remove_elf(path);
            }
        });
    }
}
