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

//! Multi-image dynamic linking for applications and runtime shared objects.
//!
//! The module owns artifact resolution, dependency discovery, symbol scope,
//! relocation, lifecycle planning and publication.

mod artifact;
mod graph;
mod lifecycle;
mod metadata;
mod publish;
mod published;
mod relocate;
mod scope;
mod session;
mod symbol;

#[cfg(test)]
pub(crate) use graph::DependencyGraph;
#[cfg(test)]
pub(crate) use session::SessionUsage;

pub(crate) use artifact::{
    ArtifactIdentity, ArtifactResolver, ArtifactRole, DependencyName, DependencyRequest,
    DependencyResolution, ImageId, ImageOwnership, ResolvedArtifact,
};

pub(crate) use published::{ImportedImageDescriptor, PublishedImageDescriptor, PublishedRegion};

pub(crate) use lifecycle::{LifecycleEntry, LifecyclePlans};
pub(crate) use metadata::{
    ImageLifecycleMetadata, ProgramHeaderGeometry, ProgramHeaderRuntimeInfo, RelocationTables,
    RuntimeImageMetadata, RuntimeImageState,
};
pub(crate) use publish::{
    CommittedImage, CommittingLinkProduct, LinkContext, LinkProduct, LinkPublisher,
    PreparedLinkManifest,
};
pub(crate) use scope::{RelocationBinding, ResolvedSymbol, ScopeSet, SymbolRegionKind};
pub(crate) use session::{DynamicLinker, SealedSession};
pub(crate) use symbol::{
    symbol_count_from_hash, SymbolBinding, SymbolDefinition, SymbolEntry, SymbolTable, SymbolType,
    SymbolVisibility,
};
