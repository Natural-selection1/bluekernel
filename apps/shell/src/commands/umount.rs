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

use crate::platform;
use std::ffi::CString;

// umount is outside std's filesystem API.
pub fn command(args: &[&str]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("Usage: unmount <target>".to_string());
    }

    let target = CString::new(args[0]).map_err(|e| e.to_string())?;
    let result = unsafe { platform::umount(target.as_ptr()) };

    if result != 0 {
        println!("mount failed (error code: {})", result);
    }

    Ok(())
}
