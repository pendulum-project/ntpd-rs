#![forbid(unsafe_code)]
#![allow(missing_docs)]

fn main() -> std::io::Result<std::process::ExitCode> {
    ntpd::ctl_main()
}
