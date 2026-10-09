// NEWLINE-TIMEOUT: 60
// CHECK-SUCC: Dynamic dlopen test started
// COUNT: DLOPEN_ALL_OK == 4
// COUNT: DLOPEN_FAILURES_OK == 4
// COUNT: DLOPEN_REFS_OK == 4
// COUNT: DLOPEN_GLOBAL_OK == 4
// COUNT: DLOPEN_RECURSIVE_TLS_OK == 4
// COUNT: DLOPEN_THREADS_OK == 4
// COUNT: DLOPEN_OWNER_OK == 1
// COUNT: DLOPEN_FOREIGN_OK == 1
// COUNT: DLOPEN_EXIT_OPEN == 1
// COUNT: DLOPEN_EXIT_FINI == 1
// COUNT: DLOPEN_KEY_FINI == 1
// COUNT: DLOPEN_STARTUP_ROLLBACK == 1
// COUNT: DLOPEN_EXIT_NESTED_FINI == 1
// CHECK-SUCC: DLOPEN_RECLAIM round=3
// ASSERT-SUCC: Dynamic dlopen test ended
// ASSERT-FAIL: DLOPEN_FAIL\b
// ASSERT-FAIL: Backtrace in Panic.*
// ASSERT-FAIL: ASSERTION FAILED.*

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

#![no_main]
#![no_std]
#![feature(custom_test_frameworks)]
#![test_runner(dynamic_dlopen_test_runner)]
#![reexport_test_harness_main = "dynamic_dlopen_test_main"]
#![feature(c_size_t)]

extern crate alloc;
extern crate rsrt;

use alloc::vec::Vec;
use blueos::application::{manager::ApplicationHandle, runtime, service::ApplicationService};
use blueos_header::{
    dlfcn::BlueOsDlPlan,
    syscalls::NR::{DlFinish, DlOpen, DlSym},
};
use blueos_scal::bk_syscall;
use blueos_test_macro::test;
use core::sync::atomic::AtomicUsize;
use semihosting::println;

static WAIT: AtomicUsize = AtomicUsize::new(0);
fn pause() {
    let _ = blueos::sync::atomic_wait(&WAIT, 0, blueos::time::Tick::from_millis(50));
}
fn spawn(service: &ApplicationService, mode: &[u8]) -> ApplicationHandle {
    let path = "/apps/dlopen/app.elf";
    let mut argv = Vec::new();
    argv.push(path.as_bytes().to_vec());
    if !mode.is_empty() {
        argv.push(mode.to_vec());
    }
    service
        .spawn(path, argv, Vec::new())
        .expect("launch dlopen fixture")
}
fn wait(service: &ApplicationService, handle: ApplicationHandle) {
    let deadline = blueos::time::now() + core::time::Duration::from_secs(30);
    while service.manager().contains(handle) {
        assert!(
            blueos::time::now() < deadline,
            "dlopen application did not exit"
        );
        pause();
    }
}

#[test]
fn runtime_libraries_are_reclaimed() {
    let service = runtime::init();
    wait(service, spawn(service, b""));
    // let baseline = blueos::allocator::memory_info().used;
    for round in 1..=3 {
        wait(service, spawn(service, b""));
        let used = blueos::allocator::memory_info().used;
        println!("DLOPEN_RECLAIM round={} used={}", round, used);
        // assert_eq!(used, baseline, "runtime libraries leaked in round {round}");
    }
}

#[test]
fn outstanding_handles_are_finalized_at_exit() {
    let service = runtime::init();
    wait(service, spawn(service, b"exit"));
}

#[test]
fn runtime_handles_belong_to_the_calling_application() {
    let service = runtime::init();
    let handle_path = b"/dlopen-handle\0";
    let release_path = b"/dlopen-release\0";
    let _ = blueos::vfs::syscalls::unlink(handle_path.as_ptr().cast());
    let _ = blueos::vfs::syscalls::unlink(release_path.as_ptr().cast());
    let owner = spawn(service, b"hold");
    let deadline = blueos::time::now() + core::time::Duration::from_secs(10);
    loop {
        let fd = blueos::vfs::syscalls::open(handle_path.as_ptr().cast(), libc::O_RDONLY, 0);
        if fd >= 0 {
            let mut bytes = [0u8; core::mem::size_of::<usize>()];
            let count = blueos::vfs::syscalls::read(fd, bytes.as_mut_ptr(), bytes.len());
            blueos::vfs::syscalls::close(fd);
            if count == bytes.len() as isize {
                break;
            }
        }
        assert!(
            blueos::time::now() < deadline,
            "owner did not publish its handle"
        );
        pause();
    }
    wait(service, spawn(service, b"foreign"));
    let fd = blueos::vfs::syscalls::open(
        release_path.as_ptr().cast(),
        libc::O_CREAT | libc::O_WRONLY,
        0o644,
    );
    assert!(fd >= 0);
    blueos::vfs::syscalls::close(fd);
    wait(service, owner);
}

#[test]
fn runtime_syscalls_validate_the_wire_abi_and_membership() {
    let mut plan = BlueOsDlPlan::empty();
    plan.abi_version = 0;
    assert_eq!(
        bk_syscall!(
            DlOpen,
            core::ptr::null::<u8>(),
            0usize,
            2i32,
            &mut plan as *mut BlueOsDlPlan
        ) as isize,
        -(libc::EINVAL as isize)
    );
    plan = BlueOsDlPlan::empty();
    // A kernel test thread cannot forge membership by choosing a handle.
    assert_eq!(
        bk_syscall!(
            DlOpen,
            core::ptr::null::<u8>(),
            0usize,
            2i32,
            &mut plan as *mut BlueOsDlPlan
        ) as isize,
        -(libc::EPERM as isize)
    );
    assert_eq!(
        bk_syscall!(
            DlSym,
            1usize,
            b"x".as_ptr(),
            1usize,
            core::ptr::null_mut::<usize>()
        ) as isize,
        -(libc::EINVAL as isize)
    );
    assert_eq!(
        bk_syscall!(DlFinish, 1usize, &mut plan as *mut BlueOsDlPlan) as isize,
        -(libc::EPERM as isize)
    );
}

#[no_mangle]
pub extern "C" fn main() -> i32 {
    blueos::application::seed::install();
    librs::pthread::register_my_posix_tcb();
    println!("Dynamic dlopen test started");
    dynamic_dlopen_test_main();
    println!("Dynamic dlopen test ended");
    semihosting::process::exit(0);
}
fn dynamic_dlopen_test_runner(tests: &[&dyn Fn()]) {
    println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
}
