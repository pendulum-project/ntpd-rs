use ntp_proto::SystemConfig;
use std::error::Error;

mod peer;
mod system;

/// Spawn the NTP daemon
pub async fn spawn(config: &SystemConfig, peer_addresses: &[&str]) -> Result<(), Box<dyn Error>> {
    system::System::spawn(config, peer_addresses).await
}
