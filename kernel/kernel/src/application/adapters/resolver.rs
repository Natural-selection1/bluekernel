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

//! File lookup policy for the loader. ELF parsing and dependency traversal
//! belong to the loader; this adapter selects exact normalized VFS paths.

use super::{system_paths::SystemLibraryPaths, vfs_reader::VfsElfReader};
use crate::{
    application::namespace::{
        resolve_dependency_paths, ApplicationNamespace, DependencyKind, ResolveBase,
    },
    error::code,
    vfs::open_path,
};
use alloc::sync::Arc;
use blueos_loader::{
    error::{ErrorContext, LoadErrorKind},
    ImageDependency, ImageHandle, LoadError, LoadResult,
};

#[derive(Clone)]
pub(crate) struct KernelSource {
    path: Arc<str>,
    shared: bool,
}

impl KernelSource {
    pub(crate) fn path(&self) -> &str {
        &self.path
    }
    pub(crate) fn shared(&self) -> bool {
        self.shared
    }
}

pub(crate) struct NamespaceSourceResolver<'a> {
    namespace: &'a ApplicationNamespace,
    catalog: &'static SystemLibraryPaths,
}

impl<'a> NamespaceSourceResolver<'a> {
    pub(crate) fn new(
        namespace: &'a ApplicationNamespace,
        catalog: &'static SystemLibraryPaths,
    ) -> Self {
        Self { namespace, catalog }
    }
    /// Select resource ownership independently of the caller's loading purpose.
    pub(crate) fn root(&self, path: &str, private: bool) -> KernelSource {
        KernelSource {
            path: Arc::from(path),
            shared: !private && self.catalog.resolve_path(path).is_some(),
        }
    }
    pub(crate) fn open(&self, source: &KernelSource) -> LoadResult<VfsElfReader> {
        open_path(source.path(), libc::O_RDONLY, 0)
            .map(VfsElfReader::new)
            .map_err(|_| backend_error())
    }
    pub(crate) fn resolve(
        &self,
        requester: &KernelSource,
        name: &[u8],
        existing: &[ImageHandle],
    ) -> LoadResult<KernelSource> {
        let request = core::str::from_utf8(name).map_err(|_| unresolved(name))?;
        let directory = parent_dir(requester.path());
        let kind = DependencyKind::classify(request);
        if matches!(kind, DependencyKind::PlainName) {
            if requester.shared() {
                let entry = self
                    .catalog
                    .resolve_name(name)
                    .ok_or_else(|| unresolved(name))?;
                return Ok(self.root(entry.path, false));
            }
            let private = resolve_dependency_paths(
                self.namespace,
                ResolveBase::RequesterDirectory(directory),
                request,
            );
            let path = private.first().ok_or_else(|| unresolved(name))?;
            if existing
                .iter()
                .any(|image| image.identity() == path.as_bytes() && !image.is_shared())
            {
                return Ok(KernelSource {
                    path: Arc::from(path.as_str()),
                    shared: false,
                });
            }
            // Only absence allows catalog fallback. A corrupt or inaccessible
            // private file remains selected and fails in the loader.
            if matches!(open_path(path, libc::O_RDONLY, 0), Err(error) if error == code::ENOENT || error == code::ENOTDIR)
            {
                if let Some(entry) = self.catalog.resolve_name(name) {
                    return Ok(self.root(entry.path, false));
                }
            }
            return Ok(self.root(path, false));
        }
        let paths = resolve_dependency_paths(
            self.namespace,
            ResolveBase::RequesterDirectory(directory),
            request,
        );
        let path = paths.first().ok_or_else(|| unresolved(name))?;
        if requester.shared() && self.catalog.resolve_path(path).is_none() {
            return Err(unresolved(name));
        }
        Ok(self.root(path, false))
    }

    pub(crate) fn source_from_snapshot(
        &self,
        dependency: &ImageDependency,
    ) -> LoadResult<KernelSource> {
        let path = core::str::from_utf8(dependency.identity()).map_err(|_| backend_error())?;
        if dependency.is_shared() && self.catalog.resolve_path(path).is_none() {
            return Err(backend_error());
        }
        Ok(KernelSource {
            path: Arc::from(path),
            shared: dependency.is_shared(),
        })
    }
}

fn parent_dir(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(0) | None => "/",
        Some(at) => &trimmed[..at],
    }
}
fn unresolved(name: &[u8]) -> LoadError {
    LoadError::new(
        LoadErrorKind::Backend,
        ErrorContext::Dependency {
            requester: 0,
            needed: name.into(),
        },
    )
}
fn backend_error() -> LoadError {
    LoadError::new(LoadErrorKind::Backend, ErrorContext::None)
}
