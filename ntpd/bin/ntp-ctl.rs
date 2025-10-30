#![forbid(unsafe_code)]

mod security;

fn main() -> std::io::Result<std::process::ExitCode> {
    use crate::security::seccomp_init;

    // Allowed syscalls
    let syscalls = vec![
        "clock_adjtime", 
        "clock_nanosleep", 
        "clone3", 
        "dup", 
        "exit_group", 
        "fchownat", 
        "futex", 
        "getdents64", 
        "getsockname", 
        "getsockopt", 
        "madvise", 
        "newfstatat", 
        "open_by_handle_at", 
        "prctl", 
        "rseq", 
        "recvmsg", 
        "sendmmsg", 
        "time", 
        "uname", 
        "writev"
    ];
    seccomp_init(syscalls);

    ntpd::ctl_main()
}