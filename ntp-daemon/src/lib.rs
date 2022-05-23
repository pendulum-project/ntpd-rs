use ntp_proto::SystemConfig;
use std::error::Error;

mod peer;
mod system;

pub async fn spawn(config: &SystemConfig, peer_addresses: &[&str]) -> Result<(), Box<dyn Error>> {
    system::start_system(config, peer_addresses).await
}
