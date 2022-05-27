use ntp_daemon::config::PeerConfig;
use ntp_proto::SystemConfig;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let config = SystemConfig::default();

    let peers = [PeerConfig::new("0.0.0.0:8080")];

    ntp_daemon::spawn(&config, &peers).await
}
