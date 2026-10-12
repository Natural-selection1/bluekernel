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

use crate::{
    api::{invalid, oom, overflow},
    dynamic_linker::{
        ArtifactIdentity, ArtifactResolver, ArtifactRole, DependencyName, DependencyRequest,
        DependencyResolution, ImageOwnership, ResolvedArtifact,
    },
    error::{ErrorContext, LoadErrorKind},
    image::ScannedArtifact,
    ImageHandle, LoadRequest, LoadResult, LoaderBackend,
};
use alloc::vec::Vec;

pub(crate) struct PlannedImage<S, R> {
    pub(crate) source: S,
    pub(crate) identity: ArtifactIdentity,
    shared: bool,
    reader: Option<R>,
    snapshot: Option<ImageHandle>,
    pub(crate) scanned: ScannedArtifact,
    traced: bool,
}
pub(crate) struct PlannedEdge {
    pub(crate) requester: usize,
    pub(crate) provider: usize,
    needed_index: u16,
}
pub(crate) struct LoadPlan<S, R> {
    pub(crate) images: Vec<PlannedImage<S, R>>,
    pub(crate) edges: Vec<PlannedEdge>,
}

impl<S, R> LoadPlan<S, R> {
    pub(crate) fn snapshots(&self) -> impl Iterator<Item = &ImageHandle> {
        self.images
            .iter()
            .filter_map(|image| image.snapshot.as_ref())
    }
    pub(crate) fn matches_snapshot(&self, image: &ImageHandle) -> bool {
        let Some(index) = self
            .images
            .iter()
            .position(|planned| planned.identity.as_bytes() == image.identity())
        else {
            return false;
        };
        let planned = &self.images[index];
        planned.shared == image.is_shared()
            && planned.scanned.role == image.descriptor.snapshot().role()
            && planned.scanned.declared_soname.as_ref() == image.descriptor.soname()
            && planned.scanned.needed.len() == image.dependencies().len()
            && image
                .dependencies()
                .iter()
                .enumerate()
                .all(|(needed_index, dependency)| {
                    planned.scanned.needed[needed_index].as_bytes() == dependency.name()
                        && self.edges.iter().any(|edge| {
                            edge.requester == index
                                && edge.needed_index as usize == needed_index
                                && self.images[edge.provider].identity.as_bytes()
                                    == dependency.identity()
                                && self.images[edge.provider].shared == dependency.is_shared()
                        })
                })
    }
    pub(crate) fn contains(&self, identity: &[u8]) -> bool {
        self.images
            .iter()
            .any(|image| image.identity.as_bytes() == identity)
    }
    pub(crate) fn connections(&self) -> LoadResult<Vec<(ArtifactIdentity, ArtifactIdentity, u16)>> {
        let mut connections = Vec::new();
        connections
            .try_reserve_exact(self.edges.len())
            .map_err(|_| oom())?;
        for edge in &self.edges {
            connections.push((
                self.images[edge.requester].identity.try_clone()?,
                self.images[edge.provider].identity.try_clone()?,
                edge.needed_index,
            ));
        }
        Ok(connections)
    }
    pub(crate) fn metadata_bytes(&self) -> LoadResult<u64> {
        let mut bytes = core::mem::size_of::<Self>() as u64
            + (self.images.capacity() * core::mem::size_of::<PlannedImage<S, R>>()) as u64
            + (self.edges.capacity() * core::mem::size_of::<PlannedEdge>()) as u64;
        for image in &self.images {
            let names = image
                .scanned
                .needed
                .iter()
                .map(|name| name.as_bytes().len() as u64)
                .sum::<u64>();
            let metadata = image.identity.metadata_bytes()
                + (image.scanned.needed.capacity() * core::mem::size_of::<DependencyName>()) as u64
                + image
                    .scanned
                    .declared_soname
                    .as_ref()
                    .map_or(0, |name| name.as_bytes().len() as u64)
                + names;
            bytes = bytes.checked_add(metadata).ok_or_else(overflow)?;
        }
        Ok(bytes)
    }
}

impl<S: Clone, R> LoadPlan<S, R> {
    pub(crate) fn build<B: LoaderBackend<Source = S, Reader = R>>(
        request: &LoadRequest<S>,
        backend: &mut B,
    ) -> LoadResult<Self> {
        if request.role == ArtifactRole::ExecutableRoot && backend.is_shared(&request.source) {
            return Err(unsupported());
        }
        let root = scan(
            backend,
            request.source.clone(),
            request.role,
            false,
            request,
        )?;
        let mut plan = Self {
            images: Vec::new(),
            edges: Vec::new(),
        };
        plan.images.try_reserve(1).map_err(|_| oom())?;
        plan.images.push(root);
        let mut queue = Vec::new();
        queue.try_reserve(1).map_err(|_| oom())?;
        queue.push((0, 1u16));
        let mut cursor = 0;
        while cursor < queue.len() {
            let (requester, depth) = queue[cursor];
            cursor += 1;
            let needed = plan.images[requester].scanned.needed.clone();
            for (needed_index, name) in needed.into_iter().enumerate() {
                request
                    .limits
                    .check_dependency_name_len(name.as_bytes().len() as u32)?;
                request
                    .limits
                    .check_dependency_edge_count((plan.edges.len() + 1) as u32)?;
                let frozen = plan.images[requester]
                    .snapshot
                    .as_ref()
                    .map(|image| &image.dependencies()[needed_index]);
                let source = if let Some(dependency) = frozen {
                    let source = backend.resolve_snapshot(dependency)?;
                    if backend.identity(&source) != dependency.identity()
                        || backend.is_shared(&source) != dependency.is_shared()
                    {
                        return Err(invalid());
                    }
                    source
                } else {
                    backend.resolve(&plan.images[requester].source, name.as_bytes())?
                };
                let reuse_required = frozen.is_some();
                let identity = backend.identity(&source);
                let shared = backend.is_shared(&source);
                let provider = if let Some(index) = plan.images.iter().position(|image| {
                    image.identity.as_bytes() == identity && image.shared == shared
                }) {
                    if plan.images[index].scanned.role != ArtifactRole::SharedObject {
                        return Err(unsupported());
                    }
                    if reuse_required && plan.images[index].snapshot.is_none() {
                        return Err(invalid());
                    }
                    index
                } else {
                    request
                        .limits
                        .check_image_count((plan.images.len() + 1) as u32)?;
                    let depth = depth.checked_add(1).ok_or_else(invalid)?;
                    request.limits.check_dependency_depth(depth)?;
                    let image = scan(
                        backend,
                        source,
                        ArtifactRole::SharedObject,
                        reuse_required,
                        request,
                    )?;
                    plan.images.try_reserve(1).map_err(|_| oom())?;
                    queue.try_reserve(1).map_err(|_| oom())?;
                    let index = plan.images.len();
                    plan.images.push(image);
                    queue.push((index, depth));
                    index
                };
                plan.edges.try_reserve(1).map_err(|_| oom())?;
                plan.edges.push(PlannedEdge {
                    requester,
                    provider,
                    needed_index: u16::try_from(needed_index).map_err(|_| overflow())?,
                });
            }
        }
        request.limits.check_image_count(plan.images.len() as u32)?;
        request
            .limits
            .check_total_runtime_metadata_bytes(plan.metadata_bytes()?)?;
        Ok(plan)
    }
}

fn scan<B: LoaderBackend>(
    backend: &mut B,
    source: B::Source,
    role: ArtifactRole,
    reuse_required: bool,
    request: &LoadRequest<B::Source>,
) -> LoadResult<PlannedImage<B::Source, B::Reader>> {
    let identity = ArtifactIdentity::from_bytes(backend.identity(&source))?;
    let shared = backend.is_shared(&source);
    if role == ArtifactRole::SharedObject {
        let snapshot = match request
            .existing
            .iter()
            .find(|image| image.identity() == identity.as_bytes())
        {
            Some(image) => Some(image.clone()),
            None => backend.snapshot(&source)?,
        };
        if let Some(snapshot) = snapshot {
            let published = snapshot.descriptor.snapshot();
            if snapshot.identity() != identity.as_bytes() || snapshot.is_shared() != shared {
                return Err(invalid());
            }
            if published.profile() != request.profile || published.role() != role {
                return Err(unsupported());
            }
            let mut needed = Vec::new();
            needed
                .try_reserve_exact(snapshot.dependencies().len())
                .map_err(|_| oom())?;
            for dependency in snapshot.dependencies() {
                request
                    .limits
                    .check_dependency_name_len(dependency.name().len() as u32)?;
                needed.push(dependency.needed().try_clone()?);
            }
            let scanned = ScannedArtifact {
                role,
                declared_soname: snapshot
                    .descriptor
                    .soname()
                    .map(DependencyName::try_clone)
                    .transpose()?,
                needed,
            };
            return Ok(PlannedImage {
                source,
                identity,
                shared,
                reader: None,
                snapshot: Some(snapshot),
                scanned,
                traced: false,
            });
        }
        if reuse_required {
            return Err(invalid());
        }
    }
    let reader = backend.open(&source)?;
    let scanned = crate::image::scan::scan_root_or_dependency(
        &reader,
        request.profile,
        role,
        *request.limits.per_image(),
    )?;
    Ok(PlannedImage {
        source,
        identity,
        shared,
        reader: Some(reader),
        snapshot: None,
        scanned,
        traced: false,
    })
}

fn unsupported() -> crate::LoadError {
    crate::LoadError::new(LoadErrorKind::UnsupportedByProfile, ErrorContext::None)
}

pub(crate) struct PlannedResolver<'a, B: LoaderBackend> {
    pub(crate) plan: &'a mut LoadPlan<B::Source, B::Reader>,
    pub(crate) backend: &'a mut B,
    pub(crate) providers: &'a [ImageHandle],
}

impl<B: LoaderBackend> PlannedResolver<'_, B> {
    pub(crate) fn load_root(&mut self) -> LoadResult<ResolvedArtifact<B::Reader>> {
        self.load_index(0, false)
    }
    fn load_index(&mut self, index: usize, trace: bool) -> LoadResult<ResolvedArtifact<B::Reader>> {
        let image = &mut self.plan.images[index];
        // Every new source transfers its original reader exactly once.
        let reader = image.reader.take().ok_or_else(invalid)?;
        let ownership = if image.shared {
            ImageOwnership::SystemCandidate
        } else {
            ImageOwnership::SessionPrivate
        };
        if trace && !image.traced {
            image.traced = true;
            let path = core::str::from_utf8(image.identity.as_bytes()).unwrap_or("<non-utf8>");
            self.backend.trace(format_args!(
                "{} path={}",
                if image.shared { "DSO_LOAD" } else { "NS_LOAD" },
                path
            ));
        }
        Ok(ResolvedArtifact::new(
            image.identity.try_clone()?,
            ownership,
            reader,
        ))
    }
    pub(crate) fn resolve_index(
        &mut self,
        index: usize,
    ) -> LoadResult<DependencyResolution<B::Reader>> {
        let image = &mut self.plan.images[index];
        if let Some(provider) = self
            .providers
            .iter()
            .find(|provider| provider.identity() == image.identity.as_bytes())
        {
            if image.shared && !image.traced {
                image.traced = true;
                self.backend.trace(format_args!(
                    "DSO_REUSE path={}",
                    core::str::from_utf8(provider.identity()).unwrap_or("<non-utf8>")
                ));
            }
            return Ok(DependencyResolution::Import(provider.imported()));
        }
        if image.reader.is_none() {
            if image.snapshot.is_some() {
                return Err(invalid());
            }
            return Ok(DependencyResolution::Existing(image.identity.try_clone()?));
        }
        self.load_index(index, true).map(DependencyResolution::Load)
    }
}

impl<B: LoaderBackend> ArtifactResolver for PlannedResolver<'_, B> {
    type Reader = B::Reader;
    fn resolve(
        &mut self,
        request: &DependencyRequest<'_>,
    ) -> LoadResult<DependencyResolution<Self::Reader>> {
        let requester = self
            .plan
            .images
            .iter()
            .position(|image| &image.identity == request.requester())
            .ok_or_else(invalid)?;
        let provider = self
            .plan
            .edges
            .iter()
            .find(|edge| {
                edge.requester == requester
                    && &self.plan.images[requester].scanned.needed[edge.needed_index as usize]
                        == request.needed()
            })
            .ok_or_else(invalid)?
            .provider;
        self.resolve_index(provider)
    }
}
