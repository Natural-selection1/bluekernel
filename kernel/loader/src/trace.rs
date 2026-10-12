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

//! Optional observations of a complete load. Events describe facts, independently
//! of a logger, output device or test framework. Borrowed data is valid only for
//! the synchronous [`crate::LoaderBackend::trace`] call.

use crate::{dynamic_linker::ImageId, LoadError};
use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadPhase {
    Discover,
    Acquire,
    /// Includes mapping, scopes, relocation, cache maintenance and sealing.
    Link,
    Publish,
    /// The backend installs the published receipt; constructors run later.
    Install,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleKind {
    Startup,
    GroupFini,
    SystemFini,
}

/// Session-local image numbers, without exposing the loader's graph types.
#[derive(Clone, Copy)]
pub struct ImageIds<'a>(&'a [ImageId]);

impl<'a> ImageIds<'a> {
    pub(crate) fn new(ids: &'a [ImageId]) -> Self {
        Self(ids)
    }
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.0.iter().map(|id| id.get())
    }
}

impl fmt::Debug for ImageIds<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub enum LoadEvent<'a> {
    Started {
        path: &'a [u8],
        executable: bool,
    },
    Phase {
        phase: LoadPhase,
        completed: bool,
    },
    Inspected {
        path: &'a [u8],
        system: bool,
        snapshot: bool,
    },
    Dependency {
        requester: &'a [u8],
        name: &'a [u8],
        provider: &'a [u8],
        frozen: bool,
    },
    Closure {
        images: usize,
        dependencies: usize,
    },
    /// A concurrent publication changed discovery's snapshot; reservations
    /// have been cancelled and discovery will restart.
    Retry,
    /// Selecting a new image for linking, not proof of successful publication.
    ImageLoadStarted {
        path: &'a [u8],
        system: bool,
    },
    ImageReused {
        path: &'a [u8],
        system: bool,
    },
    /// A computed plan entry, not an executed constructor or destructor.
    LifecyclePlan {
        kind: LifecycleKind,
        index: usize,
        owner: u32,
        address: u64,
    },
    ProviderEdge {
        requester: u32,
        provider: u32,
    },
    Image {
        owner: u32,
        soname: Option<&'a [u8]>,
        bias: u64,
    },
    Component {
        group: usize,
        members: ImageIds<'a>,
    },
    SymbolBinding {
        requester: u32,
        name: &'a [u8],
        provider: Option<u32>,
    },
    /// Publication and backend installation both succeeded.
    Completed,
    /// Emitted after cancellation and any committed receipt rollback.
    Failed {
        error: &'a LoadError,
    },
}

fn name(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes).unwrap_or("<non-utf8>")
}

/// Human-readable rendering is optional. Collectors can inspect event fields
/// directly; the loader itself never formats or sends these records.
impl fmt::Display for LoadEvent<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Started { path, executable } => write!(
                f,
                "LOAD_BEGIN purpose={} path={}",
                if *executable {
                    "executable"
                } else {
                    "shared_object"
                },
                name(path)
            ),
            Self::Phase { phase, completed } => {
                write!(f, "LOAD_PHASE phase={phase:?} completed={completed}")
            }
            Self::Inspected {
                path,
                system,
                snapshot,
            } => write!(
                f,
                "LOAD_INSPECT path={} system={system} snapshot={snapshot}",
                name(path)
            ),
            Self::Dependency {
                requester,
                name: needed,
                provider,
                frozen,
            } => write!(
                f,
                "LOAD_DEP requester={} name={} provider={} frozen={frozen}",
                name(requester),
                name(needed),
                name(provider)
            ),
            Self::Closure {
                images,
                dependencies,
            } => write!(
                f,
                "LOAD_CLOSURE images={images} dependencies={dependencies}"
            ),
            Self::Retry => f.write_str("LOAD_RETRY"),
            Self::ImageLoadStarted { path, system } => write!(
                f,
                "{}_LOAD path={}",
                if *system { "DSO" } else { "NS" },
                name(path)
            ),
            Self::ImageReused { path, system } => write!(
                f,
                "{}_REUSE path={}",
                if *system { "DSO" } else { "NS" },
                name(path)
            ),
            Self::LifecyclePlan {
                kind,
                index,
                owner,
                address,
            } => match kind {
                LifecycleKind::Startup => write!(
                    f,
                    "LIFECYCLE_INIT index={index} owner={owner} address={address:#x}"
                ),
                LifecycleKind::GroupFini => {
                    write!(f, "LIFECYCLE_GROUP_FINI index={index} owner={owner}")
                }
                LifecycleKind::SystemFini => write!(f, "LIFECYCLE_SYSTEM_FINI owner={owner}"),
            },
            Self::ProviderEdge {
                requester,
                provider,
            } => write!(f, "LINK_EDGE requester={requester} provider={provider}"),
            Self::Image {
                owner,
                soname,
                bias,
            } => write!(
                f,
                "LINK_MAP owner={owner} soname={} bias={bias:#x}",
                soname.map(name).unwrap_or("-")
            ),
            Self::Component { group, members } => {
                write!(f, "LIFECYCLE_SCC group={group} members={members:?}")
            }
            Self::SymbolBinding {
                requester,
                name: symbol,
                provider,
            } => {
                write!(
                    f,
                    "SCOPE_BIND requester={requester} name={} provider=",
                    name(symbol)
                )?;
                match provider {
                    Some(provider) => write!(f, "{provider}"),
                    None => f.write_str("none"),
                }
            }
            Self::Completed => f.write_str("LOAD_COMPLETE"),
            Self::Failed { error } => write!(f, "LOAD_FAILED error={error:?}"),
        }
    }
}
