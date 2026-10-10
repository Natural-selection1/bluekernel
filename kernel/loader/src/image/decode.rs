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

use crate::{
    address::TargetAddress,
    dynamic_linker::RuntimeImageState,
    error::{ErrorContext, LoadErrorKind},
    memory::{AllocationRollbackLog, ImageLoadTransaction, ImageMemory, SessionAllocation},
    LoadError, LoadResult,
};

#[derive(Clone, Copy)]
pub(crate) enum RelocationAddend {
    Implicit,
    Explicit(i64),
}

#[derive(Clone, Copy)]
pub(crate) struct RelocationRecord {
    offset: TargetAddress,
    raw_type: u32,
    symbol_index: u32,
    addend: RelocationAddend,
}

impl RelocationRecord {
    #[inline]
    pub const fn new(
        offset: TargetAddress,
        raw_type: u32,
        symbol_index: u32,
        addend: RelocationAddend,
    ) -> Self {
        Self {
            offset,
            raw_type,
            symbol_index,
            addend,
        }
    }

    #[inline]
    pub const fn offset(&self) -> TargetAddress {
        self.offset
    }

    #[inline]
    pub const fn raw_type(&self) -> u32 {
        self.raw_type
    }

    #[inline]
    pub const fn symbol_index(&self) -> u32 {
        self.symbol_index
    }

    #[inline]
    pub const fn addend(&self) -> RelocationAddend {
        self.addend
    }
}

#[must_use = "dropping a decoded image aborts its allocation"]
pub(crate) struct DecodedImage<M: ImageMemory> {
    pub(crate) transaction: ImageLoadTransaction<M>,
    pub(crate) runtime: RuntimeImageState,
}

/// Transfer the decoded image's unique allocation lease into the session's
/// rollback log. The transaction remains armed until transfer succeeds.
pub(crate) fn absorb_into_session<M: ImageMemory + ?Sized>(
    decoded: DecodedImage<&mut M>,
    rollback: &mut AllocationRollbackLog,
) -> LoadResult<(SessionAllocation, RuntimeImageState)> {
    let allocation = decoded.transaction.transfer_to(rollback)?;
    Ok((allocation, decoded.runtime))
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum RelocationTableKind {
    Rel,
    Rela,
}

#[derive(Default)]
pub(crate) struct RelocationTableTags {
    address: Option<u64>,
    byte_len: Option<u64>,
    entry_size: Option<u64>,
}

impl RelocationTableTags {
    /// Synthesize a JMPREL tag set whose entry size is derived from `DT_PLTREL`
    /// and the ELF class (JMPREL has no per-table `*ENT` tag).
    pub(crate) fn with_entry_size(tags: &RelocationTableTags, entry_size: u64) -> Self {
        Self {
            address: tags.address,
            byte_len: tags.byte_len,
            entry_size: Some(entry_size),
        }
    }

    #[inline]
    pub fn address(&self) -> Option<u64> {
        self.address
    }

    #[inline]
    pub fn byte_len(&self) -> Option<u64> {
        self.byte_len
    }

    #[inline]
    pub fn entry_size(&self) -> Option<u64> {
        self.entry_size
    }

    #[inline]
    pub fn address_mut(&mut self) -> &mut Option<u64> {
        &mut self.address
    }

    #[inline]
    pub fn byte_len_mut(&mut self) -> &mut Option<u64> {
        &mut self.byte_len
    }

    #[inline]
    pub fn entry_size_mut(&mut self) -> &mut Option<u64> {
        &mut self.entry_size
    }
}

#[derive(Default)]
pub(crate) struct DynamicTags {
    rel: RelocationTableTags,
    rela: RelocationTableTags,
    jmp_rel: RelocationTableTags,
    pltrel: Option<u64>,
    symtab: Option<u64>,
    syment: Option<u64>,
    strtab: Option<u64>,
    strsz: Option<u64>,
    hash: Option<u64>,
    gnu_hash: Option<u64>,
    needed: Vec<u64>,
    soname: Option<u64>,
    flags: Option<u64>,
    flags_1: Option<u64>,
    init: Option<u64>,
    fini: Option<u64>,
    preinit_array: Option<u64>,
    preinit_arraysz: Option<u64>,
    init_array: Option<u64>,
    init_arraysz: Option<u64>,
    fini_array: Option<u64>,
    fini_arraysz: Option<u64>,
}

impl DynamicTags {
    #[inline]
    pub fn rel(&self) -> &RelocationTableTags {
        &self.rel
    }

    #[inline]
    pub fn rela(&self) -> &RelocationTableTags {
        &self.rela
    }

    #[inline]
    pub fn rel_mut(&mut self) -> &mut RelocationTableTags {
        &mut self.rel
    }
    #[inline]
    pub fn rela_mut(&mut self) -> &mut RelocationTableTags {
        &mut self.rela
    }

    #[inline]
    pub fn jmp_rel(&self) -> &RelocationTableTags {
        &self.jmp_rel
    }

    #[inline]
    pub fn jmp_rel_mut(&mut self) -> &mut RelocationTableTags {
        &mut self.jmp_rel
    }

    #[inline]
    pub const fn pltrel(&self) -> Option<u64> {
        self.pltrel
    }

    #[inline]
    pub fn pltrel_mut(&mut self) -> &mut Option<u64> {
        &mut self.pltrel
    }

    #[inline]
    pub const fn symtab(&self) -> Option<u64> {
        self.symtab
    }

    #[inline]
    pub const fn syment(&self) -> Option<u64> {
        self.syment
    }

    #[inline]
    pub const fn strtab(&self) -> Option<u64> {
        self.strtab
    }

    #[inline]
    pub const fn strsz(&self) -> Option<u64> {
        self.strsz
    }

    #[inline]
    pub const fn hash(&self) -> Option<u64> {
        self.hash
    }

    #[inline]
    pub const fn gnu_hash(&self) -> Option<u64> {
        self.gnu_hash
    }

    #[inline]
    pub fn symtab_mut(&mut self) -> &mut Option<u64> {
        &mut self.symtab
    }

    #[inline]
    pub fn syment_mut(&mut self) -> &mut Option<u64> {
        &mut self.syment
    }

    #[inline]
    pub fn strtab_mut(&mut self) -> &mut Option<u64> {
        &mut self.strtab
    }

    #[inline]
    pub fn strsz_mut(&mut self) -> &mut Option<u64> {
        &mut self.strsz
    }

    #[inline]
    pub fn hash_mut(&mut self) -> &mut Option<u64> {
        &mut self.hash
    }

    #[inline]
    pub fn gnu_hash_mut(&mut self) -> &mut Option<u64> {
        &mut self.gnu_hash
    }

    #[inline]
    pub fn needed(&self) -> &[u64] {
        &self.needed
    }

    pub fn push_needed(&mut self, tag: u64, value: u64) -> LoadResult<()> {
        self.needed.try_reserve(1).map_err(|_| {
            LoadError::new(
                LoadErrorKind::OutOfMemory,
                ErrorContext::DynamicTag { tag, value },
            )
        })?;
        self.needed.push(value);
        Ok(())
    }

    #[inline]
    pub const fn soname(&self) -> Option<u64> {
        self.soname
    }

    #[inline]
    pub fn soname_mut(&mut self) -> &mut Option<u64> {
        &mut self.soname
    }

    #[inline]
    pub fn flags_mut(&mut self) -> &mut Option<u64> {
        &mut self.flags
    }

    #[inline]
    pub fn flags_1_mut(&mut self) -> &mut Option<u64> {
        &mut self.flags_1
    }

    #[inline]
    pub const fn init(&self) -> Option<u64> {
        self.init
    }

    #[inline]
    pub const fn fini(&self) -> Option<u64> {
        self.fini
    }

    #[inline]
    pub const fn preinit_array(&self) -> Option<u64> {
        self.preinit_array
    }

    #[inline]
    pub const fn preinit_arraysz(&self) -> Option<u64> {
        self.preinit_arraysz
    }

    #[inline]
    pub const fn init_array(&self) -> Option<u64> {
        self.init_array
    }

    #[inline]
    pub const fn init_arraysz(&self) -> Option<u64> {
        self.init_arraysz
    }

    #[inline]
    pub const fn fini_array(&self) -> Option<u64> {
        self.fini_array
    }

    #[inline]
    pub const fn fini_arraysz(&self) -> Option<u64> {
        self.fini_arraysz
    }

    #[inline]
    pub fn init_mut(&mut self) -> &mut Option<u64> {
        &mut self.init
    }

    #[inline]
    pub fn fini_mut(&mut self) -> &mut Option<u64> {
        &mut self.fini
    }

    #[inline]
    pub fn preinit_array_mut(&mut self) -> &mut Option<u64> {
        &mut self.preinit_array
    }

    #[inline]
    pub fn preinit_arraysz_mut(&mut self) -> &mut Option<u64> {
        &mut self.preinit_arraysz
    }

    #[inline]
    pub fn init_array_mut(&mut self) -> &mut Option<u64> {
        &mut self.init_array
    }

    #[inline]
    pub fn init_arraysz_mut(&mut self) -> &mut Option<u64> {
        &mut self.init_arraysz
    }

    #[inline]
    pub fn fini_array_mut(&mut self) -> &mut Option<u64> {
        &mut self.fini_array
    }

    #[inline]
    pub fn fini_arraysz_mut(&mut self) -> &mut Option<u64> {
        &mut self.fini_arraysz
    }
}
