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

//! Kernel ownership of committed image allocations and shared-library leases.
//! Ownership sinks are reserved before the loader transfers allocations.

use crate::application::{adapters::flat_memory::FlatImageMemory, registry::SystemDsoLease};
use alloc::vec::Vec;
use blueos_loader::{
    error::{ErrorContext, LoadErrorKind},
    memory::{AllocationLease, ImageMemory},
    CommittedAllocations, ImageHandle, LoadError, LoadResult, Publication,
};

/// Owns backing and counted registry references until installation or reaping.
/// Dropping an uninstalled receipt releases its allocations as well.
pub struct KernelLinkReceipt {
    private_allocations: Vec<AllocationLease>,
    system_allocations: Vec<AllocationLease>,
    system_images: Vec<ImageHandle>,
    system_leases: Vec<SystemDsoLease>,
    memory: FlatImageMemory,
}

impl KernelLinkReceipt {
    pub(crate) fn system_images(&self) -> &[ImageHandle] {
        &self.system_images
    }
    pub(crate) fn take_system_backings(&mut self) -> (Vec<ImageHandle>, Vec<AllocationLease>) {
        (
            core::mem::take(&mut self.system_images),
            core::mem::take(&mut self.system_allocations),
        )
    }
    pub fn retain_failed_system_allocations(&mut self, allocations: Vec<AllocationLease>) {
        debug_assert!(self.system_allocations.is_empty());
        self.system_allocations = allocations;
    }
    pub fn attach_system_leases(&mut self, leases: Vec<SystemDsoLease>) {
        self.system_leases.extend(leases);
    }
    pub fn into_parts(
        mut self,
    ) -> (
        Vec<AllocationLease>,
        Vec<AllocationLease>,
        Vec<SystemDsoLease>,
    ) {
        (
            core::mem::take(&mut self.private_allocations),
            core::mem::take(&mut self.system_allocations),
            core::mem::take(&mut self.system_leases),
        )
    }
}

impl Drop for KernelLinkReceipt {
    fn drop(&mut self) {
        for lease in self
            .private_allocations
            .drain(..)
            .chain(self.system_allocations.drain(..))
        {
            self.memory.release_committed(lease);
        }
    }
}

pub(crate) struct KernelLinkPreparedBatch {
    private: Vec<AllocationLease>,
    system: Vec<AllocationLease>,
    system_images: Vec<ImageHandle>,
}

pub(crate) struct KernelLinkPublisher {
    system_leases: Vec<SystemDsoLease>,
    memory: FlatImageMemory,
}

impl KernelLinkPublisher {
    pub(crate) fn new(memory: FlatImageMemory) -> Self {
        Self {
            memory,
            system_leases: Vec::new(),
        }
    }
    pub(crate) fn import_leases(&mut self, leases: Vec<SystemDsoLease>) {
        self.system_leases = leases;
    }
    pub(crate) fn cancel(&mut self) {
        self.system_leases.clear();
    }
    pub(crate) fn prepare(&self, publication: &Publication) -> LoadResult<KernelLinkPreparedBatch> {
        let mut private = Vec::new();
        let mut system = Vec::new();
        let mut system_images = Vec::new();
        private
            .try_reserve_exact(publication.private_images())
            .map_err(|_| publish_oom())?;
        system
            .try_reserve_exact(publication.shared_images())
            .map_err(|_| publish_oom())?;
        system_images
            .try_reserve_exact(publication.shared_images())
            .map_err(|_| publish_oom())?;
        Ok(KernelLinkPreparedBatch {
            private,
            system,
            system_images,
        })
    }
    /// The loader supplies only allocations covered by the capacity reservation.
    pub(crate) fn commit(
        &mut self,
        prepared: KernelLinkPreparedBatch,
        allocations: CommittedAllocations,
    ) -> KernelLinkReceipt {
        let KernelLinkPreparedBatch {
            mut private,
            mut system,
            mut system_images,
        } = prepared;
        for (image, lease) in allocations.into_images() {
            if image.is_shared() {
                system_images.push(image);
                system.push(lease);
            } else {
                private.push(lease);
            }
        }
        KernelLinkReceipt {
            private_allocations: private,
            system_allocations: system,
            system_images,
            system_leases: core::mem::take(&mut self.system_leases),
            memory: self.memory.clone(),
        }
    }
}
fn publish_oom() -> LoadError {
    LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None)
}
