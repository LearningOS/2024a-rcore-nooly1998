//! Process management syscalls
use crate::{
    config::{MAX_SYSCALL_NUM, PAGE_SIZE},
    mm::{translate_va_to_pa, MapPermission, PageTable, StepByOne, VirtAddr},
    task::{
        change_program_brk, current_user_token, drop_frame_area, exit_current_and_run_next,
        get_current_task_time, get_syscall_times, insert_framed_area, suspend_current_and_run_next,
        TaskStatus,
    },
    timer::get_time_us,
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();
    let _ts = translate_va_to_pa(current_user_token(), _ts as usize) as *mut TimeVal;
    unsafe {
        *_ts = TimeVal {
            sec: us / 1_000_000,
            usec: us % 1_000_000,
        };
    }
    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    trace!("kernel: sys_task_info");
    let ti = translate_va_to_pa(current_user_token(), ti as usize) as *mut TaskInfo;
    unsafe {
        (*ti).status = TaskStatus::Running;
        (*ti).syscall_times = get_syscall_times();
        (*ti).time = get_current_task_time();
    }
    0
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap");
    let start_va = VirtAddr::from(start);
    let end_va = VirtAddr::from(start + len);
    if start_va.page_offset() != 0 || port & !0x7 != 0 || port & 0x7 == 0 {
        return -1;
    }
    let mut start_vpn = start_va.floor();
    let pt = PageTable::from_token(current_user_token());
    for _ in 0..((len + PAGE_SIZE - 1) / PAGE_SIZE) {
        match pt.translate(start_vpn) {
            Some(pte) => {
                if pte.is_valid() {
                    return -1;
                }
            }
            None => {}
        }
        start_vpn.step();
    }
    let mut permissions = MapPermission::empty();
    permissions.set(MapPermission::R, port & 0x1 != 0);
    permissions.set(MapPermission::W, port & 0x2 != 0);
    permissions.set(MapPermission::X, port & 0x4 != 0);
    permissions.set(MapPermission::U, true);
    insert_framed_area(start_va, end_va, permissions);
    0
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");
    let start_va = VirtAddr::from(start);
    if start_va.page_offset() != 0 {
        return -1;
    }
    let mut start_vpn = start_va.floor();
    let end_va = VirtAddr::from(start + len);
    let pt = PageTable::from_token(current_user_token());
    for _ in 0..((len + PAGE_SIZE - 1) / PAGE_SIZE) {
        match pt.translate(start_vpn) {
            Some(pte) => {
                if !pte.is_valid() {
                    return -1;
                }
            }
            None => return -1,
        }
        start_vpn.step();
    }
    drop_frame_area(start_va, end_va);
    0
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
