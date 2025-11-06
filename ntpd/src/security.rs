use capctl::{Cap, CapSet, CapState, prctl};
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};
use std::process;

// Shared syscalls between all three user space tools.
const SHARED_SYSCALLS: [&str; 39] = [
    "access",
    "arch_prctl",
    "bind",
    "brk",
    "clock_gettime",
    "close",
    "connect",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "eventfd2",
    "execve",
    "fcntl",
    "fstat",
    "getrandom",
    "listen",
    "lseek",
    "mmap",
    "mprotect",
    "munmap",
    "openat",
    "poll",
    "pread64",
    "prlimit64",
    "rseq",
    "read",
    "recvfrom",
    "rt_sigaction",
    "rt_sigprocmask",
    "sched_getaffinity",
    "sendto",
    "set_robust_list",
    "set_tid_address",
    "setsockopt",
    "sigaltstack",
    "socket",
    "statx",
    "write",
    "ioctl",
];

pub(crate) fn seccomp_init(syscalls: Vec<&str>) {
    // Initialize the filter setting the default action to KillProcess. If a bad syscall Is made the process Is terminated by SIGSYS.
    let mut ctx = match ScmpFilterContext::new(ScmpAction::KillProcess) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: Seccomp context creation failed: {}", e);
            process::exit(1);
        }
    };
    let c_syscalls = [&SHARED_SYSCALLS[..], &syscalls[..]].concat();

    for name in c_syscalls {
        if let Err(e) = ctx.add_rule(
            ScmpAction::Allow,
            match ScmpSyscall::from_name(name) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("ERROR: Invalid syscall name {}: {}", name, e);
                    process::exit(1);
                }
            },
        ) {
            eprintln!("ERROR: Failed to add rule for {}: {}", name, e);
            process::exit(1);
        }
    }
    if let Err(e) = ctx.load() {
        eprintln!("ERROR: Seccomp load failed: {}", e);
        process::exit(1);
    }
}

pub(crate) fn drop_caps(needed: Option<&[Cap]>) {
    let capset = match needed {
        Some(needed_caps) => CapSet::from_iter(needed_caps.iter().cloned()),
        None => CapSet::empty(),
    };
    let mut current = match CapState::get_current() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ERROR: Failed to get current capabilities: {:?}", e);
            process::exit(1);
        }
    };
    current.permitted = capset.clone();
    current.inheritable = capset.clone();
    current.effective = capset.clone();
    if let Err(e) = current.set_current() {
        eprintln!("ERROR: Failed to set current capabilities: {:?}", e);
        process::exit(1);
    }
    if let Err(e) = prctl::set_no_new_privs() {
        eprintln!(
            "ERROR: Failed to enable no-new-privileges flag on current thread: {:?}",
            e
        );
        process::exit(1);
    }
}
