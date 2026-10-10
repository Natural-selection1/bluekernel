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
    image::ScannedArtifact,
    ImageHandle, LoadRequest, LoadResult, LoaderBackend,
};
use alloc::vec::Vec;

pub(crate) struct PlannedImage<S, R> {
    pub(crate) source: S,
    pub(crate) identity: ArtifactIdentity,
    shared: bool,
    reader: Option<R>,
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
        // Registry-managed sources must satisfy the shared-object contract
        // before acquiring permits, even when their ELF has a nonzero entry.
        let role = backend
            .is_shared(&request.source)
            .then_some(ArtifactRole::SharedObject);
        let root = scan(backend, request.source.clone(), role, request)?;
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
                let source = backend.resolve(&plan.images[requester].source, name.as_bytes())?;
                let identity = backend.identity(&source);
                let shared = backend.is_shared(&source);
                let provider = if let Some(index) = plan.images.iter().position(|image| {
                    image.identity.as_bytes() == identity && image.shared == shared
                }) {
                    index
                } else {
                    request
                        .limits
                        .check_image_count((plan.images.len() + 1) as u32)?;
                    let depth = depth.checked_add(1).ok_or_else(invalid)?;
                    request.limits.check_dependency_depth(depth)?;
                    let image = scan(backend, source, Some(ArtifactRole::SharedObject), request)?;
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
    role: Option<ArtifactRole>,
    request: &LoadRequest<B::Source>,
) -> LoadResult<PlannedImage<B::Source, B::Reader>> {
    let reader = backend.open(&source)?;
    let scanned = crate::image::scan::scan_root_or_dependency(
        &reader,
        request.profile,
        role,
        *request.limits.per_image(),
    )?;
    let identity = ArtifactIdentity::from_bytes(backend.identity(&source))?;
    let shared = scanned.role == ArtifactRole::SharedObject && backend.is_shared(&source);
    Ok(PlannedImage {
        source,
        identity,
        shared,
        reader: Some(reader),
        scanned,
        traced: false,
    })
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
        let reader = match image.reader.take() {
            Some(reader) => reader,
            None => self.backend.open(&image.source)?,
        };
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
