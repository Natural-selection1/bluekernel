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

//! Shell interfaces outside std, bound to the selected application runtime.

#[cfg(not(dynamic_image))]
pub use librs::direct::{mount, umount};

// Dynamic applications import C symbols from the shared libc instead of
// linking a second copy of librs and its runtime state into the executable.
#[cfg(dynamic_image)]
extern "C" {
    pub fn mount(
        source: *const libc::c_char,
        target: *const libc::c_char,
        fstype: *const libc::c_char,
        flags: libc::c_ulong,
        data: *const libc::c_void,
    ) -> libc::c_int;
    pub fn umount(target: *const libc::c_char) -> libc::c_int;
    pub fn spawn(
        path: *const libc::c_char,
        argv: *const *const libc::c_char,
        envp: *const *const libc::c_char,
    ) -> libc::c_long;
}
