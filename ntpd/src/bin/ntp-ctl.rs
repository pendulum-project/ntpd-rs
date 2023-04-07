#![forbid(unsafe_code)]

#[tokio::main]
async fn main() -> std::io::Result<std::process::ExitCode> {
    ntp_ctl::main().await
}
