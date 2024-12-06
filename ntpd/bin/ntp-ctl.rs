#![forbid(unsafe_code)]

fn main() -> std::io::Result<std::process::ExitCode> {
    ntpd::ctl_main()
}
