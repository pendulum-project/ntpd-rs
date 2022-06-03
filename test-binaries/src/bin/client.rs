use ntp_daemon::config::PeerConfig;
use ntp_proto::SystemConfig;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let config = SystemConfig::default();

    let peer_configs = [PeerConfig::new("0.0.0.0:8080")];

    let peers = Default::default();

    ntp_daemon::spawn(&config, &peer_configs, peers).await?;

    Ok(())
}
