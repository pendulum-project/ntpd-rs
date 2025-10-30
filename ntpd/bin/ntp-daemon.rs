#![forbid(unsafe_code)]

mod security;
use std::process;

fn main() {
    use crate::security::seccomp_init;
    
    // Allowed syscalls
    let syscalls = vec![
        "chmod", 
        "clock_adjtime", 
        "clone3", 
        "clone", 
        "futex", 
        "getdents64", 
        "getsockname", 
        "getsockopt", 
        "madvise", 
        "newfstatat", 
        "recvmsg", 
        "rseq", 
        "unlink", 
        "writev", 
        "prctl", 
        "clock_nanosleep", 
        "exit_group", 
        "uname", 
        "sendmmsg", 
        "exit"
    ];
    seccomp_init(syscalls);

    let result = ntpd::daemon_main();
    process::exit(if result.is_ok() { 0 } else { 1 });
}
