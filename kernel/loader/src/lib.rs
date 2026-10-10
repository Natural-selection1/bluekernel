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

//! ELF loading and dynamic linking with kernel-owned platform backends.
//!
//! Call [`load`] with a [`LoadRequest`] and a [`LoaderBackend`]. The loader
//! discovers dependencies, links and publishes the complete image closure;
//! the backend supplies file policy, memory and resource ownership.
//!
//! Core loading entry points and [`LoadError`]/[`LoadResult`] are available
//! at the crate root. Reader and memory contracts live in
//! [`reader`] and [`memory`]; ABI profiles and resource
//! limits live in [`profile`]. The [`error`] module provides error details.

extern crate alloc;

// Public API organized by responsibility.
pub mod error;
pub mod memory;
pub mod profile;
pub mod reader;

// Loading and linking implementation details.
mod address;
mod api;
mod cache;
mod dynamic_linker;
mod elf;
mod image;
mod linker;
mod memory_mapper;
mod planning;
mod relocation;

// Frequently used entry points and types.
pub use api::{
    load, CommittedAllocations, ImageHandle, LoadRequest, LoadedImage, LoaderBackend, Publication,
};
pub use error::{LoadError, LoadResult};

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
