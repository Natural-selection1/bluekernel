// NEWLINE-TIMEOUT: 60
// ASSERT-SUCC: Loader integration test ended
// ASSERT-FAIL: Backtrace in Panic.*
// ASSERT-FAIL: loader test: no stack

#![no_main]
#![no_std]
#![feature(custom_test_frameworks)]
#![test_runner(loader_test_runner)]
#![reexport_test_harness_main = "loader_test_main"]
#![feature(c_size_t)]
#![feature(thread_local)]
#![feature(c_variadic)]

extern crate alloc;
extern crate rsrt;
use alloc::{rc::Rc, sync::Arc, vec::Vec};
use blueos::{
    sync::{atomic_wait, atomic_wake},
    thread,
    time::Tick,
};
use blueos_loader as loader;
use blueos_loader::{error::LoadErrorKind, reader::ElfReader, LoadError, LoadResult};
use core::{
    cell::RefCell,
    ffi::c_char,
    sync::atomic::{AtomicUsize, Ordering},
};
use librs::pthread;
use semihosting::{
    io::{Read, Seek, SeekFrom},
    println,
};

extern "C" {
    static LOADER_TEST_ELF_PATH: *const c_char;
    static INVALID_MAGIC_ELF_PATH: *const c_char;
    static INVALID_ENTRY_ELF_PATH: *const c_char;
    static INVALID_SEGMENT_SIZE_ELF_PATH: *const c_char;
}

#[cfg(loader_test_exec)]
mod loader_test_config {
    use blueos_loader as loader;

    const fn parse_hex(value: &str) -> usize {
        let bytes = value.as_bytes();
        if bytes.len() <= 2 || bytes[0] != b'0' || (bytes[1] != b'x' && bytes[1] != b'X') {
            panic!("loader test relocation value must be hexadecimal");
        }

        let mut index = 2;
        let mut result = 0usize;
        while index < bytes.len() {
            let digit = match bytes[index] {
                b'0'..=b'9' => (bytes[index] - b'0') as usize,
                b'a'..=b'f' => (bytes[index] - b'a' + 10) as usize,
                b'A'..=b'F' => (bytes[index] - b'A' + 10) as usize,
                _ => panic!("invalid loader test relocation hex value"),
            };
            result = result * 16 + digit;
            index += 1;
        }
        result
    }

    const fn parse_permissions(value: &str) -> loader::memory::MemoryPermissions {
        let bytes = value.as_bytes();
        let mut index = 0;
        let mut permissions = loader::memory::MemoryPermissions::NONE;
        while index < bytes.len() {
            let permission = match bytes[index] {
                b'r' => loader::memory::MemoryPermissions::READ,
                b'w' => loader::memory::MemoryPermissions::WRITE,
                b'x' => loader::memory::MemoryPermissions::EXECUTE,
                _ => panic!("invalid loader test relocation permission"),
            };
            permissions = permissions.bitor(permission);
            index += 1;
        }
        permissions
    }

    pub const TEST_REGION_START: usize = parse_hex(env!("LOADER_TEST_RELOCATION_ORIGIN"));
    pub const TEST_REGION_END: usize =
        TEST_REGION_START + parse_hex(env!("LOADER_TEST_RELOCATION_LENGTH"));
    pub const TEST_REGION_PERMISSIONS: loader::memory::MemoryPermissions =
        parse_permissions(env!("LOADER_TEST_RELOCATION_PERMISSIONS"));

    pub static TEST_REGIONS: [loader::memory::MemoryRegion; 1] = [unsafe {
        loader::memory::MemoryRegion::new(
            TEST_REGION_START,
            TEST_REGION_END,
            TEST_REGION_PERMISSIONS,
        )
    }];
}

fn open_test_elf(ptr: *const core::ffi::c_char) -> semihosting::fs::File {
    let path = unsafe { core::ffi::CStr::from_ptr(ptr) };
    semihosting::fs::File::open(path).expect("open test ELF")
}

/// A seek-based `ElfReader` over a semihosting file: the image is never
/// buffered as a whole, so debug ELFs (with full debug info) load without
/// inflating the kernel heap.
#[derive(Clone, Copy)]
struct SemihostingElfReader<'a> {
    file: &'a semihosting::fs::File,
    len: u64,
}

impl<'a> SemihostingElfReader<'a> {
    fn new(file: &'a semihosting::fs::File) -> semihosting::io::Result<Self> {
        let mut file = file;
        let len = file.seek(SeekFrom::End(0))?;
        file.seek(SeekFrom::Start(0))?;
        Ok(Self { file, len })
    }
}

fn io_error() -> LoadError {
    LoadError::new(LoadErrorKind::Io, loader::error::ErrorContext::None)
}

impl ElfReader for SemihostingElfReader<'_> {
    fn len(&self) -> LoadResult<u64> {
        Ok(self.len)
    }

    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> LoadResult<()> {
        // `&File` implements Read/Seek, so a reborrow of the shared
        // reference is enough to move the file cursor.
        let mut file = self.file;
        file.seek(SeekFrom::Start(offset)).map_err(|_| io_error())?;
        let mut filled = 0;
        while filled < dst.len() {
            let n = file.read(&mut dst[filled..]).map_err(|_| io_error())?;
            if n == 0 {
                return Err(LoadError::new(
                    LoadErrorKind::OutOfBounds,
                    loader::error::ErrorContext::FileRange {
                        offset,
                        len: dst.len() as u64,
                        file_len: self.len,
                    },
                ));
            }
            filled += n;
        }
        Ok(())
    }
}

/// Stack the loader test suite runs on.
///
/// Even a rejected ELF can traverse deep parser and mapping frames. On
/// riscv64 debug, running that path on the 12 KiB harness stack overwrites the
/// adjacent main-thread control block before the next test starts. The loaded
/// program also needs room for callbacks into `librs` (`malloc`, `Box`, `Vec`).
const RUN_STACK_SIZE: usize = 64 * 1024;

/// Run the whole suite on a stack this test owns, and return once it ends.
///
/// One thread for the suite, not one per test. A thread per test keeps two
/// `RUN_STACK_SIZE` stacks (131 KiB) in the heap at once, because a worker
/// publishes its result before it has switched off its stack, so the next test
/// spawns while the previous stack is still allocated. The
/// `seeed_xiao_esp32c3` heap is only 271 KiB, and once it is fragmented that
/// way it can no longer serve `RUN_STACK_SIZE` at all: `Tlsf::map_ceil` rounds
/// the request up to the next second-level bucket, so the free blocks of
/// exactly the size being asked for - the ones the previous tests released -
/// are searched past, and `spawn_with_stack` returns `None`.
///
/// A failed spawn ends in a silent `Check Timeout`: nothing reports a panic on
/// this board (see the panic handler in `kernel/rsrt/src/lib.rs`), so the
/// checker only sees the output stop.
fn run_suite_on_own_stack() {
    let done = Arc::new(AtomicUsize::new(0));
    let worker_done = done.clone();
    let spawned = thread::spawn_with_stack(RUN_STACK_SIZE, move || {
        // The loaded program's malloc/Box/Vec path needs per-thread libc
        // state. Registering it on the one worker that outlives every test
        // also keeps the suite from leaving a POSIX TCB behind per test.
        pthread::register_my_posix_tcb();
        loader_test_main();
        worker_done.fetch_add(1, Ordering::Release);
        let _ = atomic_wake(&worker_done, usize::MAX);
    });

    if spawned.is_none() {
        // Say why, rather than letting the checker time out on a silent hang.
        println!("loader test: no stack for the {RUN_STACK_SIZE}-byte test suite");
        return;
    }

    while done.load(Ordering::Acquire) == 0 {
        // A spurious return only re-reads the flag; the worker bumps it exactly
        // once and never resets it.
        let _ = atomic_wait(&done, 0, Tick::MAX);
    }
}

mod test_elf_loader {
    #[cfg(loader_test_exec)]
    use super::loader_test_config::{
        TEST_REGIONS, TEST_REGION_END, TEST_REGION_PERMISSIONS, TEST_REGION_START,
    };
    use super::*;
    use blueos_test_macro::test;
    use loader::{
        memory::{
            AllocationLease, AllocationOffset, AllocationRequest, ImageAllocation, ImageMemory,
            ImageProtectionMemory, MemoryMapper, MemoryPermissions, MutationProgress,
            PreparedProtectionPlan, ProtectionCapabilities, ProtectionLevel,
        },
        profile::{LoadProfile, SessionLimits},
        CommittedAllocations, ImageHandle, LoadRequest, LoadedImage, LoaderBackend, Publication,
    };

    #[derive(Clone)]
    struct Memory(Rc<RefCell<MemoryMapper>>);

    impl ImageMemory for Memory {
        fn allocate_image(&mut self, request: AllocationRequest) -> LoadResult<AllocationLease> {
            self.0.borrow_mut().allocate_image(request)
        }
        fn abort_image(&mut self, lease: AllocationLease, progress: MutationProgress) {
            self.0.borrow_mut().abort_image(lease, progress);
        }
        fn release_committed(&mut self, lease: AllocationLease) {
            self.0.borrow_mut().release_committed(lease);
        }
        fn image_span(
            &self,
            allocation: &ImageAllocation,
            offset: AllocationOffset,
            len: u64,
        ) -> LoadResult<*mut u8> {
            self.0.borrow().image_span(allocation, offset, len)
        }
        fn read(
            &self,
            allocation: &ImageAllocation,
            offset: AllocationOffset,
            dst: &mut [u8],
        ) -> LoadResult<()> {
            self.0.borrow().read(allocation, offset, dst)
        }
        fn write(
            &mut self,
            allocation: &ImageAllocation,
            offset: AllocationOffset,
            bytes: &[u8],
        ) -> LoadResult<()> {
            self.0.borrow_mut().write(allocation, offset, bytes)
        }
        fn zero(
            &mut self,
            allocation: &ImageAllocation,
            offset: AllocationOffset,
            len: u64,
        ) -> LoadResult<()> {
            self.0.borrow_mut().zero(allocation, offset, len)
        }
    }
    impl ImageProtectionMemory for Memory {
        fn protect(
            &mut self,
            allocation: &ImageAllocation,
            offset: AllocationOffset,
            len: u64,
            permissions: MemoryPermissions,
        ) -> LoadResult<ProtectionLevel> {
            self.0
                .borrow_mut()
                .protect(allocation, offset, len, permissions)
        }
        fn protection_capabilities(&self) -> ProtectionCapabilities {
            self.0.borrow().protection_capabilities()
        }
        fn validate_protection_aliases(
            &self,
            allocation: &ImageAllocation,
            plan: &PreparedProtectionPlan,
        ) -> LoadResult<()> {
            self.0
                .borrow()
                .validate_protection_aliases(allocation, plan)
        }
    }
    struct Receipt {
        memory: Memory,
        leases: Vec<AllocationLease>,
    }
    impl Drop for Receipt {
        fn drop(&mut self) {
            for lease in self.leases.drain(..) {
                self.memory.release_committed(lease);
            }
        }
    }
    struct Backend<'a> {
        reader: SemihostingElfReader<'a>,
        memory: Memory,
    }
    impl<'a> LoaderBackend for Backend<'a> {
        type Source = ();
        type Reader = SemihostingElfReader<'a>;
        type Memory = Memory;
        type PreparedPublication = Vec<AllocationLease>;
        type Receipt = Receipt;
        fn identity<'b>(&self, _: &'b ()) -> &'b [u8] {
            b"test-elf"
        }
        fn is_shared(&self, _: &()) -> bool {
            false
        }
        fn open(&mut self, _: &()) -> LoadResult<Self::Reader> {
            Ok(self.reader)
        }
        fn resolve(&mut self, _: &(), _: &[u8]) -> LoadResult<()> {
            Err(io_error())
        }
        fn acquire(&mut self, _: &[()], _: &[ImageHandle]) -> LoadResult<Vec<ImageHandle>> {
            Ok(Vec::new())
        }
        fn memory(&mut self) -> Memory {
            self.memory.clone()
        }
        fn prepare_publication(
            &mut self,
            publication: &Publication,
        ) -> LoadResult<Vec<AllocationLease>> {
            let mut leases = Vec::new();
            leases
                .try_reserve_exact(publication.private_images())
                .map_err(|_| io_error())?;
            Ok(leases)
        }
        unsafe fn commit_publication(
            &mut self,
            mut leases: Vec<AllocationLease>,
            allocations: CommittedAllocations,
        ) -> Receipt {
            for (_, lease) in allocations.into_images() {
                leases.push(lease);
            }
            Receipt {
                memory: self.memory.clone(),
                leases,
            }
        }
        fn abort_publication(&mut self, receipt: Receipt) {
            drop(receipt);
        }
    }
    fn profile() -> LoadProfile {
        #[cfg(all(target_arch = "arm", target_abi = "eabihf"))]
        {
            LoadProfile::arm_thumb_hard_float()
        }
        #[cfg(all(target_arch = "arm", not(target_abi = "eabihf")))]
        {
            LoadProfile::arm_thumb_soft_float()
        }
        #[cfg(target_arch = "riscv32")]
        {
            LoadProfile::riscv32()
        }
        #[cfg(target_arch = "riscv64")]
        {
            LoadProfile::riscv64()
        }
        #[cfg(target_arch = "aarch64")]
        {
            LoadProfile::aarch64()
        }
    }
    fn load(
        reader: SemihostingElfReader<'_>,
        mapper: MemoryMapper,
    ) -> LoadResult<LoadedImage<Receipt>> {
        let mut backend = Backend {
            reader,
            memory: Memory(Rc::new(RefCell::new(mapper))),
        };
        loader::load(
            LoadRequest::new((), profile(), SessionLimits::DEFAULT),
            &mut backend,
        )
    }

    #[cfg(loader_test_exec)]
    const EXPECTED_RESULT: u32 = 0x9afc_e987;

    #[cfg(loader_test_exec)]
    static SHORT_REGIONS: [loader::memory::MemoryRegion; 1] = [unsafe {
        // SAFETY: This is a valid subset of the configured loader test range.
        loader::memory::MemoryRegion::new(
            TEST_REGION_START,
            TEST_REGION_START + 16,
            TEST_REGION_PERMISSIONS,
        )
    }];

    #[cfg(loader_test_exec)]
    static NON_EXEC_REGIONS: [loader::memory::MemoryRegion; 1] = [unsafe {
        // SAFETY: The configured region supports read and write accesses.
        loader::memory::MemoryRegion::new(
            TEST_REGION_START,
            TEST_REGION_END,
            loader::memory::MemoryPermissions::READ.bitor(loader::memory::MemoryPermissions::WRITE),
        )
    }];

    fn new_mapper() -> loader::memory::MemoryMapper {
        #[cfg(loader_test_exec)]
        {
            loader::memory::MemoryMapper::new(Some(&TEST_REGIONS))
        }
        #[cfg(not(loader_test_exec))]
        {
            loader::memory::MemoryMapper::new(None)
        }
    }

    fn assert_rejected_elf(path: *const c_char) {
        let file = open_test_elf(path);
        let reader = SemihostingElfReader::new(&file).unwrap();
        assert!(load(reader, new_mapper()).is_err());
    }

    #[test]
    fn test_load_and_run() {
        let file = open_test_elf(unsafe { LOADER_TEST_ELF_PATH });
        let reader = SemihostingElfReader::new(&file).unwrap();
        let image = load(reader, new_mapper()).expect("load ELF through the public entry");
        let entry = image.entry().unwrap().get() as usize;

        #[cfg(all(loader_test_exec))]
        {
            let run = unsafe { core::mem::transmute::<usize, extern "C" fn() -> u32>(entry) };
            assert_eq!(run(), EXPECTED_RESULT);
        }
        #[cfg(not(loader_test_exec))]
        {
            let run = unsafe { core::mem::transmute::<usize, fn()>(entry) };
            run();
        }
    }

    #[test]
    fn test_invalid_entry() {
        assert_rejected_elf(unsafe { INVALID_ENTRY_ELF_PATH });
    }

    #[test]
    fn test_invalid_magic() {
        assert_rejected_elf(unsafe { INVALID_MAGIC_ELF_PATH });
    }

    #[test]
    fn test_invalid_segment_size() {
        assert_rejected_elf(unsafe { INVALID_SEGMENT_SIZE_ELF_PATH });
    }

    #[cfg(loader_test_exec)]
    #[test]
    fn test_exec_rejects_allocated_mapper() {
        let file = open_test_elf(unsafe { LOADER_TEST_ELF_PATH });
        let reader = SemihostingElfReader::new(&file).unwrap();
        assert!(load(reader, loader::memory::MemoryMapper::new(None)).is_err());
    }

    #[cfg(loader_test_exec)]
    #[test]
    fn test_exec_rejects_out_of_range_without_writing() {
        let file = open_test_elf(unsafe { LOADER_TEST_ELF_PATH });
        let reader = SemihostingElfReader::new(&file).unwrap();
        let before = unsafe { (TEST_REGION_START as *const u32).read_volatile() };
        assert!(load(
            reader,
            loader::memory::MemoryMapper::new(Some(&SHORT_REGIONS))
        )
        .is_err());
        let after = unsafe { (TEST_REGION_START as *const u32).read_volatile() };
        assert_eq!(after, before);
    }

    #[cfg(loader_test_exec)]
    #[test]
    fn test_exec_rejects_non_executable_region() {
        let file = open_test_elf(unsafe { LOADER_TEST_ELF_PATH });
        let reader = SemihostingElfReader::new(&file).unwrap();
        assert!(load(
            reader,
            loader::memory::MemoryMapper::new(Some(&NON_EXEC_REGIONS))
        )
        .is_err());
    }
}

#[cfg_attr(compatible_old_toolchain, no_mangle)]
#[cfg_attr(not(compatible_old_toolchain), unsafe(no_mangle))]
pub fn loader_test_runner(tests: &[&dyn Fn()]) {
    println!("Loader integration test started");
    println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
    println!("Loader integration test ended");
}

#[cfg_attr(compatible_old_toolchain, no_mangle)]
#[cfg_attr(not(compatible_old_toolchain), unsafe(no_mangle))]
pub extern "C" fn main() -> i32 {
    pthread::register_my_posix_tcb();
    // The suite owns its stack, so a test that runs away on deep parser frames
    // cannot reach this thread's control block.
    run_suite_on_own_stack();
    #[cfg(coverage)]
    common_cov::write_coverage_data();
    0
}
