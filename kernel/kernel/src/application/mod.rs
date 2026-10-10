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

//! Dynamic application loading: platform adapters that bind the loader's
//! contracts (`LoaderBackend`, `ElfReader`, `ImageMemory`) to
//! the kernel's VFS, memory and cache services.
//!
//! A launch freezes an [`namespace::ApplicationNamespace`] and calls the
//! loader's complete-load interface through kernel platform services.
//! The loader owns dependency traversal and linking; the registry, thread
//! groups, runtime namespace and reaper own execution and resource lifetimes.

/// The board policy's dynamic-application profile: the single place
/// where the board ABI decides which loader profile an application links with.
/// ARM float calling conventions follow the target ABI, independently of the
/// CPU generation.
#[cfg(all(target_arch = "arm", target_feature = "mclass", target_abi = "eabi"))]
pub fn board_dynamic_profile() -> blueos_loader::profile::LoadProfile {
    blueos_loader::profile::LoadProfile::arm_thumb_soft_float()
}

#[cfg(all(target_arch = "arm", target_feature = "mclass", target_abi = "eabihf"))]
pub fn board_dynamic_profile() -> blueos_loader::profile::LoadProfile {
    blueos_loader::profile::LoadProfile::arm_thumb_hard_float()
}

#[cfg(target_arch = "riscv32")]
pub fn board_dynamic_profile() -> blueos_loader::profile::LoadProfile {
    blueos_loader::profile::LoadProfile::riscv32()
}

#[cfg(target_arch = "riscv64")]
pub fn board_dynamic_profile() -> blueos_loader::profile::LoadProfile {
    blueos_loader::profile::LoadProfile::riscv64()
}

#[cfg(target_arch = "aarch64")]
pub fn board_dynamic_profile() -> blueos_loader::profile::LoadProfile {
    blueos_loader::profile::LoadProfile::aarch64()
}

pub mod adapters;
pub mod dynamic;
pub mod group;
pub mod loader;
pub mod manager;
pub mod namespace;
pub mod publication;
pub mod reaper;
pub mod registry;
pub mod runtime;
/// Boot-time installation of the system image into the root tmpfs. Present
/// only when the board asks for it; the loader backend below is independent
/// of it, so a board whose images arrive by another route keeps `runtime`
/// without `seed`.
#[cfg(boot_dynamic_seed)]
pub mod seed;
pub mod service;
pub mod start_storage;
