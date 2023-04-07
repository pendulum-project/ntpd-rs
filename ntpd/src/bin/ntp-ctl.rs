#![forbid(unsafe_code)]

#[tokio::main]
async fn main() -> Result<std::process::ExitCode, Box<dyn std::error::Error>> {
    ntp_ctl::main().await
}
