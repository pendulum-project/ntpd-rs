#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ntp_daemon::main().await
}
