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

use alloc::vec::Vec;
use goblin::{
    elf::program_header::{
        PF_R, PF_W, PF_X, PT_ARM_EXIDX, PT_DYNAMIC, PT_GNU_EH_FRAME, PT_GNU_RELRO, PT_GNU_STACK,
        PT_INTERP, PT_LOAD, PT_NOTE, PT_PHDR, PT_TLS,
    },
    elf64,
};

const PT_RISCV_ATTRIBUTES: u32 = 0x7000_0003;

use crate::{
    address::{FileRange, TargetAddress, TargetRange},
    dynamic_linker::{ArtifactRole, ProgramHeaderGeometry},
    elf::{DynamicSegmentInfo, ElfHeaderInfo, LoadSegmentInfo, ProgramHeaderInfo},
    error::{ErrorContext, LoadErrorKind, LoadStage, ProgramHeaderField},
    image::{
        features::validate_dynamic_features,
        inspect::{InspectedImage, StackKind},
        DynamicFeatureSummary,
    },
    memory_mapper::MemoryPermissions,
    profile::{supports_segment_permissions, ElfMachine, ElfType, LoadRequest},
    reader::ElfReader,
    LoadError, LoadResult,
};

/// A dependency shared object without a `PT_DYNAMIC` has nowhere to keep its
/// dynamic symbols or relocations: malformed ELF, reported without implying a
/// `DT_SONAME` requirement.
fn missing_dynamic_error() -> LoadError {
    LoadError::new(
        LoadErrorKind::BadElf,
        ErrorContext::ProgramHeader {
            index: 0,
            field: ProgramHeaderField::Type,
            value: u64::from(PT_DYNAMIC),
        },
    )
}

pub(crate) struct AdmittedImage<R: ElfReader> {
    reader: R,
    header: ElfHeaderInfo,
    request: LoadRequest,
    file_len: u64,
    role: Option<ArtifactRole>,
}

impl<R: ElfReader> AdmittedImage<R> {
    #[inline]
    pub const fn new(
        reader: R,
        header: ElfHeaderInfo,
        request: LoadRequest,
        file_len: u64,
    ) -> Self {
        Self {
            reader,
            header,
            request,
            file_len,
            role: Some(ArtifactRole::ExecutableRoot),
        }
    }

    /// Mark this artifact as a shared object rather than the executable root.
    /// A shared object may have `e_entry == 0` and may omit `DT_SONAME`; it
    /// still requires a `PT_DYNAMIC` (checked during `inspect`).
    #[inline]
    pub(crate) const fn with_role(mut self, role: ArtifactRole) -> Self {
        self.role = Some(role);
        self
    }

    /// Infer the root role from the ELF rather than a caller-selected mode.
    pub(crate) const fn infer_role(mut self) -> Self {
        self.role = None;
        self
    }

    pub fn inspect(self) -> LoadResult<InspectedImage<R>> {
        let count = self.header.program_header_count();
        self.request
            .limits()
            .check_load_segment_count(count.into())
            .map_err(|error| error.at_stage(LoadStage::Inspect))?;
        let mut load_segments = Vec::new();
        load_segments
            .try_reserve_exact(usize::from(count))
            .map_err(|_| {
                LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None)
                    .at_stage(LoadStage::Inspect)
            })?;

        let entry_size = usize::from(self.header.program_header_entry_size());
        let mut raw = [0; elf64::program_header::SIZEOF_PHDR];
        let mut dynamic = None;
        let mut relro = None;
        let mut stack = StackKind::NotDeclared;
        let mut interpreter = None;
        let mut tls = None;
        let mut phdr_vaddr = None;

        for index in 0..count {
            let offset = self
                .header
                .program_header_offset()
                .checked_add(u64::from(index) * u64::from(self.header.program_header_entry_size()))
                .ok_or_else(|| {
                    program_header_error(index, ProgramHeaderField::FileRange, 0)
                        .at_stage(LoadStage::Inspect)
                })?;
            self.reader
                .read_exact_at(offset, &mut raw[..entry_size])
                .map_err(|error| error.at_stage(LoadStage::Inspect))?;
            let program_header = ProgramHeaderInfo::decode(
                &raw[..entry_size],
                self.request.profile().class(),
                self.request.profile().endian(),
            )
            .map_err(|e| e.at_stage(LoadStage::Inspect))?;

            match program_header.r#type() {
                PT_LOAD => {
                    if program_header.file_size() > program_header.memory_size() {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::FileRange,
                            program_header.file_size(),
                        )
                        .at_stage(LoadStage::Inspect));
                    }
                    let permissions = permissions_from_flags(program_header.flags());
                    if !supports_segment_permissions(permissions) {
                        return Err(LoadError::new(
                            LoadErrorKind::UnsupportedByProfile,
                            ErrorContext::ProgramHeader {
                                index,
                                field: ProgramHeaderField::Permissions,
                                value: u64::from(permissions.bits()),
                            },
                        )
                        .at_stage(LoadStage::Inspect));
                    }
                    let file_range =
                        FileRange::new(program_header.file_offset(), program_header.file_size());
                    file_range
                        .validate(self.file_len)
                        .map_err(|e| e.at_stage(LoadStage::Inspect))?;
                    TargetRange::new(program_header.vaddr(), program_header.memory_size())
                        .end()
                        .map_err(|e| e.at_stage(LoadStage::Inspect))?;
                    load_segments.push(LoadSegmentInfo::new(
                        index,
                        file_range,
                        program_header.vaddr(),
                        program_header.memory_size(),
                        program_header.align(),
                        permissions,
                    ));
                }
                PT_DYNAMIC => {
                    if dynamic.is_some() {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::DuplicateDynamic,
                            program_header.r#type().into(),
                        )
                        .at_stage(LoadStage::Inspect));
                    }
                    let file_range =
                        FileRange::new(program_header.file_offset(), program_header.file_size());
                    file_range
                        .validate(self.file_len)
                        .map_err(|e| e.at_stage(LoadStage::Inspect))?;
                    TargetRange::new(program_header.vaddr(), program_header.memory_size())
                        .end()
                        .map_err(|e| e.at_stage(LoadStage::Inspect))?;
                    dynamic = Some(DynamicSegmentInfo::new(
                        file_range,
                        program_header.vaddr(),
                        program_header.memory_size(),
                    ))
                }
                PT_GNU_RELRO => {
                    if relro.is_some() {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::DuplicateRelro,
                            program_header.r#type().into(),
                        )
                        .at_stage(LoadStage::Inspect));
                    }
                    let target_range =
                        TargetRange::new(program_header.vaddr(), program_header.memory_size());
                    target_range
                        .end()
                        .map_err(|error| error.at_stage(LoadStage::Inspect))?;
                    relro = Some(target_range);
                }
                PT_GNU_STACK => {
                    if stack != StackKind::NotDeclared {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::DuplicateStack,
                            program_header.r#type().into(),
                        )
                        .at_stage(LoadStage::Inspect));
                    }
                    if program_header.flags() & PF_X != 0 {
                        stack = StackKind::Executable;
                    } else {
                        stack = StackKind::NonExecutable
                    }
                }
                PT_INTERP => {
                    if interpreter.is_some() {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::DuplicateInterpreter,
                            program_header.r#type().into(),
                        )
                        .at_stage(LoadStage::Inspect));
                    }
                    let file_range =
                        FileRange::new(program_header.file_offset(), program_header.file_size());
                    file_range
                        .validate(self.file_len)
                        .map_err(|e| e.at_stage(LoadStage::Inspect))?;
                    interpreter = Some(file_range);
                }
                PT_TLS => {
                    if tls.is_some() {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::DuplicateTls,
                            program_header.r#type().into(),
                        )
                        .at_stage(LoadStage::Inspect));
                    }
                    if program_header.file_size() > program_header.memory_size() {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::FileRange,
                            program_header.file_size(),
                        )
                        .at_stage(LoadStage::Inspect));
                    }
                    let file_range =
                        FileRange::new(program_header.file_offset(), program_header.file_size());
                    file_range
                        .validate(self.file_len)
                        .map_err(|e| e.at_stage(LoadStage::Inspect))?;
                    let target_range =
                        TargetRange::new(program_header.vaddr(), program_header.memory_size());
                    target_range
                        .end()
                        .map_err(|e| e.at_stage(LoadStage::Inspect))?;
                    tls = Some(target_range)
                }
                PT_PHDR => {
                    if phdr_vaddr.is_some() {
                        return Err(program_header_error(
                            index,
                            ProgramHeaderField::DuplicatePhdr,
                            program_header.r#type().into(),
                        )
                        .at_stage(LoadStage::Inspect));
                    }
                    phdr_vaddr = Some(program_header.vaddr());
                }
                PT_GNU_EH_FRAME => {}
                // Notes are structurally harmless metadata. The runtime loader
                // does not currently interpret their contents.
                PT_NOTE => {}
                PT_ARM_EXIDX if self.header.machine() == ElfMachine::Arm => {}
                PT_RISCV_ATTRIBUTES if self.header.machine() == ElfMachine::Riscv => {}
                t => {
                    return Err(LoadError::new(
                        LoadErrorKind::UnsupportedByProfile,
                        ErrorContext::ProgramHeader {
                            index,
                            field: ProgramHeaderField::UnknownField,
                            value: t.into(),
                        },
                    )
                    .at_stage(LoadStage::Inspect));
                }
            }
        }
        if stack == StackKind::Executable {
            return Err(LoadError::new(
                LoadErrorKind::UnsupportedByProfile,
                ErrorContext::ProgramHeader {
                    index: 0,
                    field: ProgramHeaderField::ExecutableStack,
                    value: 0,
                },
            )
            .at_stage(LoadStage::Inspect));
        }
        if interpreter.is_some() {
            return Err(LoadError::new(
                LoadErrorKind::UnsupportedByProfile,
                ErrorContext::ProgramHeader {
                    index: 0,
                    field: ProgramHeaderField::UnsupportedInterpreter,
                    value: 0,
                },
            )
            .at_stage(LoadStage::Inspect));
        }
        if tls.is_some() {
            return Err(LoadError::new(
                LoadErrorKind::UnsupportedByProfile,
                ErrorContext::ProgramHeader {
                    index: 0,
                    field: ProgramHeaderField::UnsupportedTls,
                    value: 0,
                },
            )
            .at_stage(LoadStage::Inspect));
        }

        // The dynamic feature summary must be decided here, before
        // any allocation or write. A `PT_DYNAMIC` that requests an unsupported
        // feature is rejected while the write count is still zero.
        //
        // A dependency shared object must still carry a `PT_DYNAMIC` — its
        // symbols and relocations live there — but a missing table is a plain
        // malformed-ELF condition, not a SONAME one: the root and static
        // PIEs legitimately have none.
        let summary = match dynamic.as_ref() {
            Some(dynamic) => validate_dynamic_features(
                &self.reader,
                dynamic,
                self.header.class(),
                self.header.endian(),
                self.request.limits(),
            )
            .map_err(|error| error.at_stage(LoadStage::Inspect))?,
            None => DynamicFeatureSummary::empty(),
        };

        // ET_EXEC and an explicitly marked PIE are executable roots. Older
        // PIE toolchains may omit DF_1_PIE; a SONAME-less root with an entry
        // still supplies an executable entry. A DSO with no entry needs no
        // caller-selected shared mode.
        let role = self.role.unwrap_or_else(|| {
            if self.header.r#type() == ElfType::Exec
                || summary.is_pie()
                || (self.header.entry() != 0 && summary.soname().is_none())
            {
                ArtifactRole::ExecutableRoot
            } else {
                ArtifactRole::SharedObject
            }
        });
        if role == ArtifactRole::SharedObject {
            if self.header.r#type() != ElfType::Dyn || summary.is_pie() {
                return Err(LoadError::new(
                    LoadErrorKind::UnsupportedByProfile,
                    ErrorContext::HeaderField {
                        field: crate::error::HeaderField::Type,
                        value: u64::from(self.header.r#type()),
                    },
                )
                .at_stage(LoadStage::Inspect));
            }
            if dynamic.is_none() {
                return Err(missing_dynamic_error().at_stage(LoadStage::Inspect));
            }
        }

        // GNU ld does not necessarily emit PT_PHDR for a PIE even when the
        // program-header table is part of a mapped PT_LOAD. In that common
        // layout, derive the table's virtual address from the segment's
        // file-to-virtual mapping so the application can receive AT_PHDR.
        if phdr_vaddr.is_none() {
            let phdr_file_len = u64::from(self.header.program_header_entry_size())
                * u64::from(self.header.program_header_count());
            let phdr_file_range =
                FileRange::new(self.header.program_header_offset(), phdr_file_len);
            phdr_vaddr = infer_program_header_vaddr(phdr_file_range, &load_segments)
                .map_err(|error| error.at_stage(LoadStage::Inspect))?;
        }

        let phdr_geometry = ProgramHeaderGeometry::new(
            self.header.program_header_entry_size(),
            self.header.program_header_count(),
            phdr_vaddr,
        );

        Ok(InspectedImage::new(
            self.reader,
            self.request,
            self.header,
            load_segments,
            dynamic,
            relro,
            stack,
            summary,
            phdr_geometry,
        )
        .with_role(role))
    }
}

/// Find the program-header table in a mapped file range and translate its
/// file offset to the corresponding ELF virtual address.
fn infer_program_header_vaddr(
    program_headers: FileRange,
    load_segments: &[LoadSegmentInfo],
) -> LoadResult<Option<TargetAddress>> {
    let program_headers_end = program_headers.end()?;
    for segment in load_segments {
        let file_range = segment.file_range();
        if program_headers.offset() < file_range.offset()
            || program_headers_end > file_range.end()?
        {
            continue;
        }
        let offset_in_segment = program_headers.offset() - file_range.offset();
        return segment.vaddr().checked_add(offset_in_segment).map(Some);
    }
    Ok(None)
}

fn permissions_from_flags(flags: u32) -> MemoryPermissions {
    let mut permissions = MemoryPermissions::NONE;
    if flags & PF_R != 0 {
        permissions = permissions.bitor(MemoryPermissions::READ);
    }
    if flags & PF_W != 0 {
        permissions = permissions.bitor(MemoryPermissions::WRITE);
    }
    if flags & PF_X != 0 {
        permissions = permissions.bitor(MemoryPermissions::EXECUTE);
    }
    permissions
}

pub(crate) fn program_header_error(index: u16, field: ProgramHeaderField, value: u64) -> LoadError {
    LoadError::new(
        LoadErrorKind::BadElf,
        ErrorContext::ProgramHeader {
            index,
            field,
            value,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use blueos_test_macro::test;

    #[test]
    fn infers_program_header_vaddr_from_containing_load_segment() {
        let load_segments = [LoadSegmentInfo::new(
            0,
            FileRange::new(0x20, 0x200),
            TargetAddress::new(0x1000),
            0x200,
            4,
            MemoryPermissions::READ,
        )];

        let actual =
            infer_program_header_vaddr(FileRange::new(0x34, 0xc0), &load_segments).unwrap();

        assert_eq!(actual, Some(TargetAddress::new(0x1014)));
    }

    #[test]
    fn leaves_program_header_vaddr_absent_when_table_is_not_mapped() {
        let load_segments = [LoadSegmentInfo::new(
            0,
            FileRange::new(0x100, 0x100),
            TargetAddress::new(0x2000),
            0x100,
            4,
            MemoryPermissions::READ,
        )];

        let actual =
            infer_program_header_vaddr(FileRange::new(0x34, 0xc0), &load_segments).unwrap();

        assert_eq!(actual, None);
    }
}
