use ntp_daemon::config::PeerConfig;
use ntp_proto::SystemConfig;
use std::{error::Error, sync::Arc};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let config = Arc::new(RwLock::new(SystemConfig::default()));

    let peer_configs = [PeerConfig::try_from("0.0.0.0:8080").unwrap()];

    let peers = Default::default();
    let system = Default::default();

    ntp_daemon::spawn(config, &peer_configs, peers, system).await?;

    Ok(())
}
