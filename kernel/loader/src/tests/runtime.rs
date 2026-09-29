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
    dynamic_linker::{DependencyGraph, ScopeSet, SessionUsage, SymbolTable},
    reader::SliceElfReader,
    tests::fixture::{ElfFixtureBuilder, RecordingMemory},
    ArtifactIdentity, ArtifactResolver, DependencyRequest, DependencyResolution, DynamicLinker,
    ElfClass, ElfData, ElfType, FileIdentity, ImageOwnership, ImportedImageDescriptor,
    LoadErrorKind, LoadLimits, LoadProfile, LoadResult, ProgramHeaderRuntimeInfo,
    PublishedImageDescriptor, ResolvedArtifact, Riscv64Relocator, SessionLimits, TargetAddress,
};
use goblin::elf::header::{EM_RISCV, ET_DYN};
use std::{cell::RefCell, rc::Rc, sync::Arc, vec::Vec};

fn identity(name: &[u8]) -> ArtifactIdentity {
    ArtifactIdentity::new(FileIdentity::from_bytes(name))
}

// A real decoded hash/symbol table: one named SHN_ABS symbol and the ELF
// null entry. This also exercises absolute address zero without a fake lookup.
fn symbols(binding: u8, visibility: u8, defined: bool, value: u64) -> SymbolTable {
    let mut bytes = std::vec![0u8; 48];
    bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
    bytes[28] = binding << 4;
    bytes[29] = visibility;
    bytes[30..32].copy_from_slice(&(if defined { 0xfff1u16 } else { 0 }).to_le_bytes());
    bytes[32..40].copy_from_slice(&value.to_le_bytes());
    let hash = [1u32, 2, 1, 0, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    SymbolTable::decode(
        &bytes,
        b"\0probe\0".to_vec(),
        ElfClass::Elf64,
        ElfData::Little,
        TargetAddress::new(0x10000),
        &[],
        false,
        256,
        None,
        Some(hash),
    )
    .expect("decode symbol table")
}

fn descriptor(name: &[u8], table: SymbolTable) -> Arc<PublishedImageDescriptor> {
    let mut graph = DependencyGraph::new(SessionLimits::DEFAULT);
    let root = graph
        .insert_root(identity(name), None, ImageOwnership::SessionPrivate)
        .unwrap();
    Arc::new(
        PublishedImageDescriptor::from_node_and_state(
            graph.node(root).unwrap(),
            Vec::new(),
            Vec::new(),
            TargetAddress::new(0),
            ProgramHeaderRuntimeInfo::empty(),
            table,
        )
        .unwrap(),
    )
}

struct NoDependencies;
impl ArtifactResolver for NoDependencies {
    type Reader = SliceElfReader<'static>;
    fn resolve(
        &mut self,
        _: &DependencyRequest<'_>,
    ) -> LoadResult<DependencyResolution<Self::Reader>> {
        panic!("an already-published empty closure must not call its resolver")
    }
}

#[test]
fn runtime_shared_root_accepts_zero_entry_without_weakening_executable_admission() {
    let bytes = ElfFixtureBuilder::elf64(EM_RISCV, ET_DYN)
        .with_load_segment(0x1000, 0x200, 0x200, 4)
        // ELF64 headers put DT_NULL at file offset 176, 112 bytes after
        // the load segment's file offset 64.
        .with_dynamic_segment(0x1070)
        .build();
    let sink = Rc::new(RefCell::new(None));
    let mut memory = RecordingMemory::new(sink.clone());
    let executable = DynamicLinker::new(Riscv64Relocator).begin(
        ResolvedArtifact::new(
            identity(b"app"),
            ImageOwnership::SessionPrivate,
            SliceElfReader::new(&bytes),
        ),
        LoadProfile::riscv64(ElfType::Dyn),
        SessionLimits::DEFAULT,
        &mut memory,
    );
    assert!(executable.is_err());
    drop(executable);
    assert!(RecordingMemory::recorded(&sink).is_none());

    let mut shared = DynamicLinker::new(Riscv64Relocator)
        .begin_shared(
            DependencyResolution::Load(ResolvedArtifact::new(
                identity(b"dso"),
                ImageOwnership::SessionPrivate,
                SliceElfReader::new(&bytes),
            )),
            LoadProfile::riscv64(ElfType::Dyn),
            SessionLimits::DEFAULT,
            &mut memory,
        )
        .unwrap();
    shared.close_dependencies(&mut NoDependencies).unwrap();
    let relocated = shared.freeze_scopes().unwrap().relocate().unwrap();
    drop(relocated);
    assert!(RecordingMemory::recorded(&sink).is_some());
}

#[test]
fn runtime_imported_root_and_duplicate_scope_do_not_allocate_backings() {
    let provider = descriptor(b"ready", SymbolTable::empty());
    let sink = Rc::new(RefCell::new(None));
    let mut memory = RecordingMemory::new(sink.clone());
    let mut shared = DynamicLinker::new(Riscv64Relocator)
        .begin_shared::<SliceElfReader<'static>, _>(
            DependencyResolution::Import(ImportedImageDescriptor::namespace(provider.clone())),
            LoadProfile::riscv64(ElfType::Dyn),
            SessionLimits::DEFAULT,
            &mut memory,
        )
        .unwrap();
    shared
        .import_scope(std::vec![
            ImportedImageDescriptor::namespace(provider.clone()),
            ImportedImageDescriptor::namespace(provider)
        ])
        .unwrap();
    shared.close_dependencies(&mut NoDependencies).unwrap();
    drop(shared.freeze_scopes().unwrap().relocate().unwrap());
    assert!(RecordingMemory::recorded(&sink).is_none());
}

#[test]
fn failed_runtime_scope_import_poisoning_prevents_partial_publication() {
    let limits = SessionLimits::new(
        LoadLimits::DEFAULT,
        1,
        1024,
        32,
        1 << 28,
        1 << 28,
        1 << 23,
        1 << 26,
        256,
        256,
    );
    let sink = Rc::new(RefCell::new(None));
    let mut memory = RecordingMemory::new(sink.clone());
    let mut shared = DynamicLinker::new(Riscv64Relocator)
        .begin_shared::<SliceElfReader<'static>, _>(
            DependencyResolution::Import(ImportedImageDescriptor::namespace(descriptor(
                b"root",
                SymbolTable::empty(),
            ))),
            LoadProfile::riscv64(ElfType::Dyn),
            limits,
            &mut memory,
        )
        .unwrap();
    let error = shared
        .import_scope(std::vec![ImportedImageDescriptor::namespace(descriptor(
            b"excess",
            SymbolTable::empty()
        ))])
        .unwrap_err();
    assert!(matches!(error.kind(), LoadErrorKind::ResourceLimit));
    assert!(shared.close_dependencies(&mut NoDependencies).is_err());
    assert!(shared.freeze_scopes().is_err());
    assert!(RecordingMemory::recorded(&sink).is_none());
}

#[test]
fn runtime_global_prefix_precedes_local_closure_but_cannot_interpose_system() {
    let mut graph = DependencyGraph::new(SessionLimits::DEFAULT);
    let root = graph
        .insert_root(identity(b"root"), None, ImageOwnership::SessionPrivate)
        .unwrap();
    let global = graph
        .insert_scope_provider(identity(b"global"), None, ImageOwnership::NamespaceReady)
        .unwrap();
    let system = graph
        .insert_scope_provider(identity(b"system"), None, ImageOwnership::ExternalReady)
        .unwrap();
    let scopes = ScopeSet::freeze_with_prefix(&graph, &[global, system]).unwrap();
    let tables = [
        symbols(1, 0, true, 11),
        symbols(1, 0, true, 22),
        symbols(1, 0, true, 33),
    ];
    let tables: Vec<_> = tables.iter().collect();
    let mut usage = SessionUsage::default();
    let result = scopes
        .resolve_name(&tables, root, b"probe", &SessionLimits::DEFAULT, &mut usage)
        .unwrap()
        .unwrap();
    assert_eq!(result.address().get(), 22);
    let result = scopes
        .resolve_name(
            &tables,
            system,
            b"probe",
            &SessionLimits::DEFAULT,
            &mut usage,
        )
        .unwrap()
        .unwrap();
    assert_eq!(result.address().get(), 33);
}

#[test]
fn runtime_symbol_lookup_filters_visibility_binding_and_undefined_entries() {
    for (binding, visibility, defined, export) in [
        (1, 0, true, true),
        (2, 0, true, true),
        (1, 3, true, true),
        (0, 0, true, false),
        (1, 1, true, false),
        (1, 2, true, false),
        (1, 0, false, false),
    ] {
        let image = descriptor(b"symbol", symbols(binding, visibility, defined, 123));
        assert_eq!(image.lookup_export(b"probe").is_some(), export);
        assert!(image.lookup_export(b"missing").is_none());
    }
    let zero = descriptor(b"zero", symbols(1, 0, true, 0));
    assert_eq!(zero.lookup_export(b"probe"), Some(TargetAddress::new(0)));
}
