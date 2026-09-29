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

use blueos_header::dlfcn::{BlueOsDlPlan, DL_PLAN_ABI_VERSION};
use core::ffi::c_long;

#[cfg(all(enable_vfs, dynamic_loader))]
mod enabled {
    use super::*;
    use crate::{
        application::{dynamic::RuntimeNamespace, group::ThreadGroup, service::ApplicationService},
        scheduler,
        thread::Thread,
    };
    use alloc::{sync::Arc, vec::Vec};

    fn current() -> Result<(ThreadGroup, Arc<RuntimeNamespace>, usize), i32> {
        let id = Thread::id(&scheduler::current_thread());
        let service = ApplicationService::get().ok_or(libc::ENOSYS)?;
        let group = service.manager().group_for_thread(id).ok_or(libc::EPERM)?;
        let runtime = group.runtime().ok_or(libc::EINVAL)?;
        Ok((group, runtime, id))
    }

    fn bytes(ptr: *const u8, len: usize) -> Result<Vec<u8>, i32> {
        if ptr.is_null() || len == 0 || len > 256 {
            return Err(libc::EINVAL);
        }
        // Shared-flat copy-in contract: the caller owns the pointer range;
        // length, NUL and UTF-8 rules are bounded before linking starts.
        let src = unsafe { core::slice::from_raw_parts(ptr, len) };
        if src.contains(&0) {
            return Err(libc::EINVAL);
        }
        let mut owned = Vec::new();
        owned.try_reserve_exact(len).map_err(|_| libc::ENOMEM)?;
        owned.extend_from_slice(src);
        Ok(owned)
    }

    pub fn open(path: *const u8, len: usize, flags: i32) -> Result<BlueOsDlPlan, i32> {
        let (group, runtime, thread) = current()?;
        let owned = if path.is_null() {
            if len != 0 {
                return Err(libc::EINVAL);
            }
            None
        } else {
            Some(bytes(path, len)?)
        };
        let path = owned
            .as_deref()
            .map(core::str::from_utf8)
            .transpose()
            .map_err(|_| libc::EINVAL)?;
        let cwd = crate::vfs::get_working_dir().get_full_path();
        runtime.open(&group, path, &cwd, flags, thread)
    }
    pub fn symbol(handle: usize, name: *const u8, len: usize) -> Result<usize, i32> {
        let (_, runtime, thread) = current()?;
        runtime.symbol(handle, &bytes(name, len)?, thread)
    }
    pub fn close(handle: usize) -> Result<BlueOsDlPlan, i32> {
        let (_, runtime, thread) = current()?;
        runtime.close(handle, thread)
    }
    pub fn finish(token: usize) -> Result<BlueOsDlPlan, i32> {
        let (_, runtime, thread) = current()?;
        runtime.finish(token, thread)
    }
    pub fn exit() -> Result<BlueOsDlPlan, i32> {
        let (_, runtime, thread) = current()?;
        runtime.exit(thread)
    }
}

#[cfg(not(all(enable_vfs, dynamic_loader)))]
mod enabled {
    use super::*;
    pub fn open(_: *const u8, _: usize, _: i32) -> Result<BlueOsDlPlan, i32> {
        Err(libc::ENOSYS)
    }
    pub fn symbol(_: usize, _: *const u8, _: usize) -> Result<usize, i32> {
        Err(libc::ENOSYS)
    }
    pub fn close(_: usize) -> Result<BlueOsDlPlan, i32> {
        Err(libc::ENOSYS)
    }
    pub fn finish(_: usize) -> Result<BlueOsDlPlan, i32> {
        Err(libc::ENOSYS)
    }
    pub fn exit() -> Result<BlueOsDlPlan, i32> {
        Err(libc::ENOSYS)
    }
}

fn valid_plan(ptr: *mut BlueOsDlPlan) -> bool {
    if ptr.is_null() || ptr as usize % core::mem::align_of::<BlueOsDlPlan>() != 0 {
        return false;
    }
    let plan = unsafe { &*ptr };
    plan.abi_version == DL_PLAN_ABI_VERSION
        && plan.struct_size as usize >= core::mem::size_of::<BlueOsDlPlan>()
}

fn plan_result(ptr: *mut BlueOsDlPlan, call: impl FnOnce() -> Result<BlueOsDlPlan, i32>) -> c_long {
    if !valid_plan(ptr) {
        return -(libc::EINVAL as c_long);
    }
    match call() {
        Ok(plan) => {
            unsafe {
                *ptr = plan;
            }
            0
        }
        Err(errno) => -(errno as c_long),
    }
}

pub fn open(path: *const u8, len: usize, flags: i32, plan: *mut BlueOsDlPlan) -> c_long {
    plan_result(plan, || enabled::open(path, len, flags))
}
pub fn close(handle: usize, plan: *mut BlueOsDlPlan) -> c_long {
    plan_result(plan, || enabled::close(handle))
}
pub fn finish(token: usize, plan: *mut BlueOsDlPlan) -> c_long {
    plan_result(plan, || enabled::finish(token))
}
pub fn exit(plan: *mut BlueOsDlPlan) -> c_long {
    plan_result(plan, enabled::exit)
}
pub fn symbol(handle: usize, name: *const u8, len: usize, result: *mut usize) -> c_long {
    if result.is_null() || result as usize % core::mem::align_of::<usize>() != 0 {
        return -(libc::EINVAL as c_long);
    }
    match enabled::symbol(handle, name, len) {
        Ok(address) => {
            unsafe {
                *result = address;
            }
            0
        }
        Err(errno) => -(errno as c_long),
    }
}
