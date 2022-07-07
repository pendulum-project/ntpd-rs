use ntp_daemon::config::PeerConfig;
use ntp_proto::SystemConfig;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let peer_configs = [PeerConfig::try_from("0.0.0.0:8080").unwrap()];

    let (handle, _) = ntp_daemon::spawn(SystemConfig::default(), &peer_configs).await?;

    handle.await??;

    Ok(())
}
