use ntp_daemon::config::{ClockConfig, CombinedSynchronizationConfig, KeysetConfig, PeerConfig};
use ntp_proto::PeerDefaultsConfig;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let peer_configs = [PeerConfig::try_from("0.0.0.0:8080").unwrap()];

    // we always generate the keyset (even if NTS is not used)
    let keyset = ntp_daemon::nts_key_provider::spawn(KeysetConfig::default()).await;

    let (handle, _) = ntp_daemon::spawn(
        CombinedSynchronizationConfig::default(),
        PeerDefaultsConfig::default(),
        ClockConfig::default(),
        &peer_configs,
        &[],
        keyset,
    )
    .await?;

    handle.await??;

    Ok(())
}
