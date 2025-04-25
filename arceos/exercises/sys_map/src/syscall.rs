#![allow(dead_code)]

use api::get_file_like;
use arceos_posix_api as api;
use axerrno::LinuxError;
use axfs::fops::File;
use axhal::arch::TrapFrame;
use axhal::mem::VirtAddr;
use axhal::paging::MappingFlags;
use axhal::trap::{register_trap_handler, PAGE_FAULT, SYSCALL};
use axtask::current;
use axtask::TaskExtRef;
use core::ffi::{c_char, c_int, c_void};
use core::ops::Deref;
use memory_addr::{MemoryAddr, VirtAddrRange};

const SYS_IOCTL: usize = 29;
const SYS_OPENAT: usize = 56;
const SYS_CLOSE: usize = 57;
const SYS_READ: usize = 63;
const SYS_WRITE: usize = 64;
const SYS_WRITEV: usize = 66;
const SYS_EXIT: usize = 93;
const SYS_EXIT_GROUP: usize = 94;
const SYS_SET_TID_ADDRESS: usize = 96;
const SYS_MMAP: usize = 222;

const AT_FDCWD: i32 = -100;

/// Macro to generate syscall body
///
/// It will receive a function which return Result<_, LinuxError> and convert it to
/// the type which is specified by the caller.
#[macro_export]
macro_rules! syscall_body {
    ($fn: ident, $($stmt: tt)*) => {{
        #[allow(clippy::redundant_closure_call)]
        let res = (|| -> axerrno::LinuxResult<_> { $($stmt)* })();
        match res {
            Ok(_) | Err(axerrno::LinuxError::EAGAIN) => debug!(concat!(stringify!($fn), " => {:?}"),  res),
            Err(_) => info!(concat!(stringify!($fn), " => {:?}"), res),
        }
        match res {
            Ok(v) => v as _,
            Err(e) => {
                -e.code() as _
            }
        }
    }};
}

bitflags::bitflags! {
    #[derive(Debug)]
    /// permissions for sys_mmap
    ///
    /// See <https://github.com/bminor/glibc/blob/master/bits/mman.h>
    struct MmapProt: i32 {
        /// Page can be read.
        const PROT_READ = 1 << 0;
        /// Page can be written.
        const PROT_WRITE = 1 << 1;
        /// Page can be executed.
        const PROT_EXEC = 1 << 2;
    }
}

impl From<MmapProt> for MappingFlags {
    fn from(value: MmapProt) -> Self {
        let mut flags = MappingFlags::USER;
        if value.contains(MmapProt::PROT_READ) {
            flags |= MappingFlags::READ;
        }
        if value.contains(MmapProt::PROT_WRITE) {
            flags |= MappingFlags::WRITE;
        }
        if value.contains(MmapProt::PROT_EXEC) {
            flags |= MappingFlags::EXECUTE;
        }
        flags
    }
}

bitflags::bitflags! {
    #[derive(Debug)]
    /// flags for sys_mmap
    ///
    /// See <https://github.com/bminor/glibc/blob/master/bits/mman.h>
    struct MmapFlags: i32 {
        /// Share changes
        const MAP_SHARED = 1 << 0;
        /// Changes private; copy pages on write.
        const MAP_PRIVATE = 1 << 1;
        /// Map address must be exactly as requested, no matter whether it is available.
        const MAP_FIXED = 1 << 4;
        /// Don't use a file.
        const MAP_ANONYMOUS = 1 << 5;
        /// Don't check for reservations.
        const MAP_NORESERVE = 1 << 14;
        /// Allocation is for a stack.
        const MAP_STACK = 0x20000;
    }
}

#[register_trap_handler(SYSCALL)]
fn handle_syscall(tf: &TrapFrame, syscall_num: usize) -> isize {
    ax_println!("handle_syscall [{}] ...", syscall_num);
    let ret = match syscall_num {
        SYS_IOCTL => sys_ioctl(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _,
        SYS_SET_TID_ADDRESS => sys_set_tid_address(tf.arg0() as _),
        SYS_OPENAT => sys_openat(
            tf.arg0() as _,
            tf.arg1() as _,
            tf.arg2() as _,
            tf.arg3() as _,
        ),
        SYS_CLOSE => sys_close(tf.arg0() as _),
        SYS_READ => sys_read(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
        SYS_WRITE => sys_write(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
        SYS_WRITEV => sys_writev(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
        SYS_EXIT_GROUP => {
            ax_println!("[SYS_EXIT_GROUP]: system is exiting ..");
            axtask::exit(tf.arg0() as _)
        }
        SYS_EXIT => {
            ax_println!("[SYS_EXIT]: system is exiting ..");
            axtask::exit(tf.arg0() as _)
        }
        SYS_MMAP => sys_mmap(
            tf.arg0() as _,
            tf.arg1() as _,
            tf.arg2() as _,
            tf.arg3() as _,
            tf.arg4() as _,
            tf.arg5() as _,
        ),
        _ => {
            ax_println!("Unimplemented syscall: {}", syscall_num);
            -LinuxError::ENOSYS.code() as _
        }
    };
    ret
}

#[register_trap_handler(PAGE_FAULT)]
fn handle_page_fault(vaddr: VirtAddr, access_flags: MappingFlags, is_user: bool) -> bool {
    if is_user {
        if !axtask::current()
            .task_ext()
            .aspace
            .lock()
            .handle_page_fault(vaddr, access_flags)
        {
            ax_println!("{}: segmentation fault, exit!", axtask::current().id_name());
            axtask::exit(-1);
        } else {
            ax_println!("{}: handle page fault OK!", axtask::current().id_name());
        }
        true
    } else {
        false
    }
}

#[allow(unused_variables)]
fn sys_mmap(
    addr: *mut usize,
    length: usize,
    prot: i32,
    flags: i32,
    _fd: i32,
    _offset: isize,
) -> isize {
    if length == 0 {
        return -LinuxError::EINVAL.code() as _;
    }
    let Some(prot) = MmapProt::from_bits(prot) else {
        return -LinuxError::EINVAL.code() as _;
    };
    let Some(flags) = MmapFlags::from_bits(flags) else {
        return -LinuxError::EINVAL.code() as _;
    };

    if flags.contains(MmapFlags::MAP_SHARED) && flags.contains(MmapFlags::MAP_PRIVATE) {
        return -LinuxError::EINVAL.code() as _;
    }

    let file_read = !flags.contains(MmapFlags::MAP_ANONYMOUS) && _fd != AT_FDCWD;

    let mut vaddr = VirtAddr::from_usize(addr as _);
    let align_length = length.align_up_4k();
    let mapping_flags = if file_read {
        MappingFlags::from(prot).union(MappingFlags::WRITE)
    } else {
        MappingFlags::from(prot)
    };

    let cur = current();
    let mut aspace = cur.task_ext().aspace.lock();

    if flags.contains(MmapFlags::MAP_FIXED) {
        if !vaddr.is_aligned_4k() {
            return -LinuxError::EINVAL.code() as _;
        }

        if let Err(e) = aspace.unmap(vaddr, align_length) {
            ax_println!("sys_mmap unmap failed: {:?}", e);
        }

        match aspace.map_alloc(vaddr, align_length, mapping_flags, true) {
            Ok(_) => {}
            Err(e) => {
                ax_println!("sys_mmap fixed mapping failed: {:?}", e);
                return -e.code() as _;
            }
        }
    } else {
        let limit = VirtAddrRange::new(aspace.base(), aspace.base() + aspace.size());
        let hint = vaddr;

        let Some(free_addr) = aspace.find_free_area(hint, align_length, limit) else {
            return -LinuxError::ENOMEM.code() as _;
        };

        match aspace.map_alloc(free_addr, align_length, mapping_flags, true) {
            Ok(_) => {
                vaddr = free_addr;
            }
            Err(e) => {
                ax_println!("sys_mmap allocation failed: {:?}", e);
                return -e.code() as _;
            }
        }
    }

    if file_read {
        let Ok(file) = get_file_like(_fd).map_err(|_| LinuxError::EBADF) else {
            let _ = aspace.unmap(vaddr, align_length);
            return -LinuxError::EBADF.code() as _;
        };

        let mut remain = length;
        let mut cur_offset = _offset as usize;
        let mut cur_addr = vaddr.as_usize();

        while remain > 0 {
            let chunk_size = remain.min(4096);
            let buf = unsafe { core::slice::from_raw_parts_mut(cur_addr as *mut u8, chunk_size) };

            match file.read_at(cur_offset as _, buf) {
                Ok(_) => {}
                Err(e) => {
                    ax_println!("sys_mmap read failed: {:?}", e);
                    let _ = aspace.unmap(vaddr, align_length);
                    return -e.code() as _;
                }
            }

            cur_addr += chunk_size;
            cur_offset += chunk_size;
            remain -= chunk_size;
        }
    }

    vaddr.as_usize() as isize
}

fn sys_openat(dfd: c_int, fname: *const c_char, flags: c_int, mode: api::ctypes::mode_t) -> isize {
    assert_eq!(dfd, AT_FDCWD);
    api::sys_open(fname, flags, mode) as isize
}

fn sys_close(fd: i32) -> isize {
    api::sys_close(fd) as isize
}

fn sys_read(fd: i32, buf: *mut c_void, count: usize) -> isize {
    api::sys_read(fd, buf, count)
}

fn sys_write(fd: i32, buf: *const c_void, count: usize) -> isize {
    api::sys_write(fd, buf, count)
}

fn sys_writev(fd: i32, iov: *const api::ctypes::iovec, iocnt: i32) -> isize {
    unsafe { api::sys_writev(fd, iov, iocnt) }
}

fn sys_set_tid_address(tid_ptd: *const i32) -> isize {
    let curr = current();
    curr.task_ext().set_clear_child_tid(tid_ptd as _);
    curr.id().as_u64() as isize
}

fn sys_ioctl(_fd: i32, _op: usize, _argp: *mut c_void) -> i32 {
    ax_println!("Ignore SYS_IOCTL");
    0
}
