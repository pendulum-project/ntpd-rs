use std::{net::IpAddr, sync::Arc};

use timestamped_socket::interface::{interfaces, ChangeDetector};
use tokio::sync::watch;

pub fn spawn() -> std::io::Result<watch::Receiver<Arc<[IpAddr]>>> {
    let mut change_listener = ChangeDetector::new()?;
    let local_ips: Arc<[IpAddr]> = interfaces()?
        .iter()
        .flat_map(|(_, interface)| interface.ips())
        .collect();

    let (writer, reader) = watch::channel(local_ips);

    tokio::spawn(async move {
        loop {
            change_listener.wait_for_change().await;
            match interfaces() {
                Ok(interfaces) => {
                    let _ = writer.send(
                        interfaces
                            .iter()
                            .flat_map(|(_, interface)| interface.ips())
                            .collect(),
                    );
                }
                Err(e) => {
                    tracing::warn!("Could not get new list of which ip addresses the interfaces in the system have: {}", e);
                }
            }
        }
    });

    Ok(reader)
}
