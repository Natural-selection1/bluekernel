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

#![no_std]

//! Preserve the existing dynamic-ELF checker records without sending loader
//! diagnostics through the UART while applications are printing. Only test
//! binaries depend on this collector; the production kernel owns no buffer.

extern crate alloc;

use alloc::vec::Vec;
use blueos::{
    application::trace::{self, Event},
    sync::SpinLock,
};
use blueos_loader::trace::LoadEvent;
use core::fmt::{self, Write};

// One allocation before the tests. Appending observations never grows the
// buffer, so collecting a trace cannot look like a per-launch heap leak.
const DEFAULT_CAPACITY: usize = 128 * 1024;
const RECORD_CAPACITY: usize = 1024;

struct Capture {
    bytes: Vec<u8>,
    active: bool,
    overflow: bool,
    required: usize,
    oversized: usize,
}

static CAPTURE: SpinLock<Capture> = SpinLock::new(Capture {
    bytes: Vec::new(),
    active: false,
    overflow: false,
    required: 0,
    oversized: 0,
});

struct Record {
    bytes: [u8; RECORD_CAPACITY],
    len: usize,
}

impl Write for Record {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        let dst = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        dst.copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

fn observe(event: Event<'_>) {
    // The scope corpus checks these three bindings. Other relocated symbols
    // are validated by executing the fixtures; buffering every libc binding
    // would make observation memory scale with the runtime's symbol count.
    if let Event::Load {
        event: LoadEvent::SymbolBinding { name, .. },
        ..
    } = event
    {
        if ![b"missing_data".as_slice(), b"sys_target", b"strlen"].contains(&name) {
            return;
        }
    }
    let mut record = Record {
        bytes: [0; RECORD_CAPACITY],
        len: 0,
    };
    // Formatting is outside the lock. The lock covers only a bounded memory
    // copy, with no allocation, device access or scheduling operation.
    let formatted = writeln!(&mut record, "{event}").is_ok();
    let mut capture = CAPTURE.irqsave_lock();
    if !capture.active {
        return;
    }
    if !formatted {
        capture.oversized += 1;
        capture.overflow = true;
        return;
    }
    capture.required += record.len;
    if record.len > capture.bytes.capacity() - capture.bytes.len() {
        capture.overflow = true;
        return;
    }
    capture.bytes.extend_from_slice(&record.bytes[..record.len]);
}

/// Call before the first test launches an application.
pub fn start() {
    start_with_capacity(DEFAULT_CAPACITY);
}

/// Select an explicit batch bound for a corpus that performs many loads.
pub fn start_with_capacity(capacity: usize) {
    let bytes = Vec::with_capacity(capacity);
    {
        let mut capture = CAPTURE.irqsave_lock();
        assert!(!capture.active, "dynamic trace collection already started");
        capture.bytes = bytes;
        capture.active = true;
        capture.overflow = false;
        capture.required = 0;
        capture.oversized = 0;
    }
    assert!(
        trace::install(observe),
        "application trace observer already installed"
    );
}

/// Call after all applications under test have been reaped, before the final
/// checker success marker. Records retain collection order and load identity;
/// that order does not impose an execution order across independent loads.
pub fn finish() {
    let (bytes, overflow, required, oversized) = {
        let mut capture = CAPTURE.irqsave_lock();
        capture.active = false;
        (
            core::mem::take(&mut capture.bytes),
            capture.overflow,
            capture.required,
            capture.oversized,
        )
    };
    let capacity = bytes.capacity();
    assert!(
        !overflow,
        "dynamic trace capture overflow: required={required} capacity={capacity} oversized={oversized} record_capacity={RECORD_CAPACITY}"
    );
    use semihosting::io::Write;
    let mut stdout = semihosting::io::stdout().expect("trace stdout");
    // Keep each host operation bounded to one complete record, even when a
    // corpus collected hundreds of KiB. No application producer remains.
    for record in bytes.split_inclusive(|byte| *byte == b'\n') {
        let mut remaining = record;
        let deadline = blueos::time::now() + core::time::Duration::from_secs(10);
        while !remaining.is_empty() {
            match stdout.write(remaining) {
                Ok(0) => panic!("trace stdout made no progress"),
                Ok(written) => remaining = &remaining[written..],
                // QEMU can return the full length unwritten when its checker
                // pipe is full, without updating SYS_ERRNO. The vendored I/O
                // wrapper turns that zero progress into an error, even errno
                // zero. For this known-valid stdout handle, retry the unwritten
                // suffix with a bound; a permanent error still fails the test.
                Err(error) => {
                    assert!(
                        blueos::time::now() < deadline,
                        "trace stdout blocked: {error:?}"
                    );
                    static WAIT: core::sync::atomic::AtomicUsize =
                        core::sync::atomic::AtomicUsize::new(0);
                    let _ = blueos::sync::atomic_wait(&WAIT, 0, blueos::time::Tick::from_millis(1));
                }
            }
        }
    }
}
