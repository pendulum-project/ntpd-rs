use ntp_proto::SystemConfig;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let config = SystemConfig::default();

    let peer_addresses = [
        // "0.pool.ntp.org:123",
        // "1.pool.ntp.org:123",
        // "2.pool.ntp.org:123",
        // "3.pool.ntp.org:123",
        "0.0.0.0:8080",
    ];

    ntp_daemon::spawn(&config, &peer_addresses).await
}
