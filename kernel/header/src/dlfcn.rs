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

//! Runtime linking wire ABI. Handles and operation tokens are opaque integers,
//! never pointers into kernel objects. Function arrays stay pinned until the
//! matching DlFinish. The application executes them outside all loader locks.

pub const DL_PLAN_ABI_VERSION: u32 = 1;
pub const RTLD_LAZY: i32 = 1;
pub const RTLD_NOW: i32 = 2;
pub const RTLD_LOCAL: i32 = 0;
pub const RTLD_GLOBAL: i32 = 0x100;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BlueOsDlPlan {
    pub abi_version: u32,
    pub struct_size: u32,
    pub handle: usize,
    pub token: usize,
    pub entries: *const usize,
    pub count: usize,
    /// Report an initialization error after its rollback fini plan completes.
    pub error: i32,
}

impl BlueOsDlPlan {
    pub const fn empty() -> Self {
        Self {
            abi_version: DL_PLAN_ABI_VERSION,
            struct_size: core::mem::size_of::<Self>() as u32,
            handle: 0,
            token: 0,
            entries: core::ptr::null(),
            count: 0,
            error: 0,
        }
    }
}
