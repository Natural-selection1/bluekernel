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
    LoadError, LoadResult,
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
    /// Select resource ownership; the loader determines the ELF object type.
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

#[cfg(test)]
mod tests {
    use super::{super::system_paths::SystemLibraryEntry, *};
    use blueos_test_macro::test;
    static CATALOG: SystemLibraryPaths = SystemLibraryPaths::new(&[SystemLibraryEntry {
        lookup_name: b"libextra.so",
        path: "/system/lib/libextra.so",
        keep_cached: false,
    }]);
    fn c_path<const N: usize>(path: &str) -> [core::ffi::c_char; N] {
        assert!(path.len() < N, "test path too long: {path}");
        let mut buffer = [0 as core::ffi::c_char; N];
        for (byte, slot) in path.bytes().zip(buffer.iter_mut()) {
            *slot = byte as core::ffi::c_char;
        }
        buffer
    }

    fn write_file(path: &str, bytes: &[u8]) {
        let c_path = c_path::<64>(path);
        let fd = crate::vfs::syscalls::open(
            c_path.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
            0o644,
        );
        assert!(fd > 0, "open {path} for write: {fd}");
        let wrote = crate::vfs::syscalls::write(fd, bytes.as_ptr(), bytes.len());
        assert_eq!(wrote as usize, bytes.len(), "write {path}");
        crate::vfs::syscalls::close(fd);
    }

    fn make_dir(path: &str) {
        let c_path = c_path::<64>(path);
        let rc = crate::vfs::syscalls::mkdir(c_path.as_ptr(), 0o755);
        // Tests share the root tmpfs; a directory a previous test seeded is
        // fine to reuse, exactly as the boot seeder tolerates EEXIST.
        assert!(rc == 0 || rc == -libc::EEXIST, "mkdir {path}: {rc}");
    }

    /// Remove a file, tolerating ENOENT (a fresh tmpfs never had it).
    fn remove_file(path: &str) {
        let c_path = c_path::<64>(path);
        let rc = crate::vfs::syscalls::unlink(c_path.as_ptr());
        assert!(rc == 0 || rc == -libc::ENOENT, "unlink {path}: {rc}");
    }

    fn with_resolver(run: impl FnOnce(NamespaceSourceResolver<'_>, KernelSource)) {
        make_dir("/apps");
        make_dir("/apps/resolve-test");
        make_dir("/apps/resolve-test/lib");
        remove_file("/apps/resolve-test/lib/libextra.so");
        let namespace = ApplicationNamespace::from_launch_path(
            "app.elf",
            "/apps/resolve-test",
            crate::application::board_dynamic_profile(),
        )
        .unwrap();
        let resolver = NamespaceSourceResolver::new(&namespace, &CATALOG);
        let root = resolver.root(namespace.root_path(), true);
        run(resolver, root);
    }
    #[test]
    fn resolve_relative_from_requester_directory() {
        with_resolver(|resolver, root| {
            let image = resolver
                .resolve(&root, b"./lib/../lib/libextra.so")
                .unwrap();
            assert_eq!(image.path(), "/apps/resolve-test/lib/libextra.so");
            assert!(!image.shared());
        });
    }
    #[test]
    fn resolve_catalog_absolute_path_as_shared() {
        with_resolver(|resolver, root| {
            let image = resolver.resolve(&root, b"/system/lib/libextra.so").unwrap();
            assert!(image.shared());
        });
    }
    #[test]
    fn resolve_missing_private_file_uses_catalog() {
        with_resolver(|resolver, root| {
            let image = resolver.resolve(&root, b"libextra.so").unwrap();
            assert_eq!(image.path(), "/system/lib/libextra.so");
            assert!(image.shared());
        });
    }
    #[test]
    fn resolve_present_broken_private_file_keeps_exact_path() {
        with_resolver(|resolver, root| {
            write_file("/apps/resolve-test/lib/libextra.so", &[0; 16]);
            let image = resolver.resolve(&root, b"libextra.so").unwrap();
            assert_eq!(image.path(), "/apps/resolve-test/lib/libextra.so");
            assert!(!image.shared());
        });
    }
    #[test]
    fn resolve_system_requester_never_uses_application_files() {
        with_resolver(|resolver, _| {
            write_file("/apps/resolve-test/lib/libextra.so", &[0; 16]);
            let system = resolver.root("/system/lib/libextra.so", false);
            assert_eq!(
                resolver.resolve(&system, b"libextra.so").unwrap().path(),
                system.path()
            );
            assert!(resolver
                .resolve(&system, b"/apps/resolve-test/lib/libextra.so")
                .is_err());
            assert!(resolver.resolve(&system, b"libunknown.so").is_err());
        });
    }
}
