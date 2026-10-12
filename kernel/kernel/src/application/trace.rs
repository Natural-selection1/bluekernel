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

//! Opt-in application observations. Install an observer before launching any
//! applications. By default no detailed loader trace is generated or printed.
//! An observer receives borrowed facts synchronously; it must copy anything it
//! retains, must not panic, and must not reenter loading or application control.
//! No kernel lock is held by this dispatcher while calling the observer.

use super::manager::ApplicationHandle;
use blueos_loader::trace::LoadEvent;
use core::{
    cell::Cell,
    fmt,
    sync::atomic::{AtomicUsize, Ordering},
};
use spin::Once;

pub type Observer = for<'a> fn(Event<'a>);

static OBSERVER: Once<Observer> = Once::new();
static NEXT_LOAD: AtomicUsize = AtomicUsize::new(1);

/// Install the process-lifetime observer once. Returns false if already set.
/// Observers should collect records or counters; device output is a separate
/// concern and must not extend an interrupt-masked critical section.
pub fn install(observer: Observer) -> bool {
    let installed = Cell::new(false);
    OBSERVER.call_once(|| {
        installed.set(true);
        observer
    });
    installed.get()
}

pub(crate) fn enabled() -> bool {
    OBSERVER.get().is_some()
}

pub(super) fn new_load_id() -> usize {
    if enabled() {
        NEXT_LOAD.fetch_add(1, Ordering::Relaxed)
    } else {
        0
    }
}

/// Returns whether an observer received the record. Callers may use ordinary
/// debug logging as a fallback for the small application lifecycle summaries.
pub(crate) fn emit(event: Event<'_>) -> bool {
    match OBSERVER.get() {
        Some(observer) => {
            observer(event);
            true
        }
        None => false,
    }
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub enum Event<'a> {
    Load {
        application: Option<ApplicationHandle>,
        /// Unique for each exec/dlopen operation, including repeated loads in
        /// the same application. Image numbers are local to this operation.
        operation: usize,
        event: LoadEvent<'a>,
    },
    Launched {
        handle: ApplicationHandle,
        path: &'a str,
    },
    InitComplete {
        handle: ApplicationHandle,
    },
    Reaped {
        handle: ApplicationHandle,
        private_images: usize,
        imported_dsos: usize,
    },
    /// Every destructor in this shared image's plan has returned.
    DsoFini {
        path: &'a [u8],
    },
    /// The backing was released, after all destructors in its SCC returned.
    DsoUnload {
        path: &'a [u8],
    },
}

impl fmt::Display for Event<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Load { application, operation, event } => {
                match application {
                    Some(handle) => write!(f, "[APP:{}:{} LOAD:{operation}] ", handle.slot, handle.generation)?,
                    None => write!(f, "[LOAD:{operation}] ")?,
                }
                fmt::Display::fmt(event, f)
            }
            Self::Launched { handle, path } => write!(f,
                "APP_LAUNCHED handle={}:{} path={path}", handle.slot, handle.generation),
            Self::InitComplete { handle } => write!(f,
                "APP_INIT_COMPLETE handle={}:{}", handle.slot, handle.generation),
            Self::Reaped { handle, private_images, imported_dsos } => write!(f,
                "APP_REAP handle={}:{} private_images={private_images} imported_dsos={imported_dsos}",
                handle.slot, handle.generation),
            Self::DsoFini { path } => write!(f, "DSO_FINI path={}", core::str::from_utf8(path).unwrap_or("<non-utf8>")),
            Self::DsoUnload { path } => write!(f, "DSO_UNLOAD path={}", core::str::from_utf8(path).unwrap_or("<non-utf8>")),
        }
    }
}
