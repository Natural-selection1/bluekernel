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

use std::{ffi::CString, ptr};

use crate::platform;

pub fn command(args: &[&str]) -> Result<(), String> {
    if args.is_empty() {
        return Err("Usage: run <path> [arg...]".to_string());
    }

    let storage: Vec<CString> = args
        .iter()
        .map(|arg| CString::new(*arg))
        .collect::<Result<_, _>>()
        .map_err(|error| error.to_string())?;
    let mut argv: Vec<*const libc::c_char> = storage.iter().map(|arg| arg.as_ptr()).collect();
    argv.push(ptr::null());
    let envp = [ptr::null()];

    // The owned strings and null-terminated arrays remain live through spawn;
    // the syscall copies the arguments before returning.
    let result = unsafe { platform::spawn(argv[0], argv.as_ptr(), envp.as_ptr()) };
    if result < 0 {
        return Err(format!("spawn failed: errno {}", -result));
    }
    println!("launched handle {}", result);
    Ok(())
}
