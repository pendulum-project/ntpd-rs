#![forbid(unsafe_code)]

#[tokio::main]
async fn main() -> std::io::Result<std::process::ExitCode> {
    ntpd::ctl_main().await
}
