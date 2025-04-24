#![allow(dead_code)]

use axhal::arch::TrapFrame;
use axhal::trap::{register_trap_handler, PAGE_FAULT, SYSCALL};
use axerrno::LinuxError;
use axtask::TaskExtRef;
use axhal::paging::MappingFlags;
use axhal::mem::VirtAddr;

const SYS_EXIT: usize = 93;

#[register_trap_handler(SYSCALL)]
fn handle_syscall(tf: &TrapFrame, syscall_num: usize) -> isize {
    ax_println!("handle_syscall ...");
    let ret = match syscall_num {
        SYS_EXIT => {
            ax_println!("[SYS_EXIT]: process is exiting ..");
            axtask::exit(tf.arg0() as _)
        },
        _ => {
            ax_println!("Unimplemented syscall: {}", syscall_num);
            -LinuxError::ENOSYS.code() as _
        }
    };
    ret
}

#[register_trap_handler(PAGE_FAULT)]
fn handle_page_fault(vaddr: VirtAddr, access_flags: MappingFlags, is_user:bool) -> bool {
    ax_println!("handle_page_fault: {:#x?}", vaddr);

    if !is_user {
        return false
    }

    let cur = axtask::current();
    if cur.task_ext().aspace.lock().handle_page_fault(vaddr, access_flags) {
        ax_println!("{}: handle page fault OK!", cur.id_name());
        true
    } else {
        ax_println!("{}: segmentation fault, exit!", cur.id_name());
        false
    }
}