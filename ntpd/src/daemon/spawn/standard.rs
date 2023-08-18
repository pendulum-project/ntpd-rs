use std::{net::SocketAddr, ops::Deref};

use thiserror::Error;
use tokio::sync::mpsc;
use tracing::warn;

use super::super::config::StandardPeerConfig;

use super::{
    BasicSpawner, PeerId, PeerRemovalReason, PeerRemovedEvent, SpawnAction, SpawnEvent, SpawnerId,
};

pub struct StandardSpawner {
    id: SpawnerId,
    config: StandardPeerConfig,
    network_wait_period: std::time::Duration,
    resolved: Option<SocketAddr>,
}

#[derive(Error, Debug)]
pub enum StandardSpawnError {
    #[error("Channel send error: {0}")]
    SendError(#[from] mpsc::error::SendError<SpawnEvent>),
}

impl StandardSpawner {
    pub fn new(
        config: StandardPeerConfig,
        network_wait_period: std::time::Duration,
    ) -> StandardSpawner {
        StandardSpawner {
            id: Default::default(),
            config,
            network_wait_period,
            resolved: None,
        }
    }

    async fn do_resolve(&mut self, force_resolve: bool) -> SocketAddr {
        if let (false, Some(addr)) = (force_resolve, self.resolved) {
            addr
        } else {
            let addr = loop {
                match self.config.address.lookup_host().await {
                    Ok(mut addresses) => match addresses.next() {
                        None => {
                            warn!("Could not resolve peer address, retrying");
                            tokio::time::sleep(self.network_wait_period).await;
                        }
                        Some(first) => {
                            break first;
                        }
                    },
                    Err(e) => {
                        warn!(error = ?e, "error while resolving peer address, retrying");
                        tokio::time::sleep(self.network_wait_period).await;
                    }
                }
            };
            self.resolved = Some(addr);
            addr
        }
    }

    async fn spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), StandardSpawnError> {
        let addr = self.do_resolve(false).await;
        action_tx
            .send(SpawnEvent::new(
                self.id,
                SpawnAction::create(
                    PeerId::new(),
                    addr,
                    self.config.address.deref().clone(),
                    None,
                ),
            ))
            .await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl BasicSpawner for StandardSpawner {
    type Error = StandardSpawnError;

    async fn handle_init(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), StandardSpawnError> {
        self.spawn(action_tx).await
    }

    async fn handle_peer_removed(
        &mut self,
        removed_peer: PeerRemovedEvent,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), StandardSpawnError> {
        if removed_peer.reason == PeerRemovalReason::Unreachable {
            // force new resolution
            self.resolved = None;
        }
        if removed_peer.reason != PeerRemovalReason::Demobilized {
            self.spawn(action_tx).await
        } else {
            Ok(())
        }
    }

    fn get_id(&self) -> SpawnerId {
        self.id
    }

    fn get_addr_description(&self) -> String {
        self.config.address.to_string()
    }

    fn get_description(&self) -> &str {
        "standard"
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::mpsc::{self, error::TryRecvError};

    use crate::daemon::{
        config::{NormalizedAddress, StandardPeerConfig},
        spawn::{
            standard::StandardSpawner, tests::get_create_params, PeerRemovalReason, Spawner,
            SystemEvent,
        },
        system::{MESSAGE_BUFFER_SIZE, NETWORK_WAIT_PERIOD},
    };

    #[tokio::test]
    async fn creates_a_peer() {
        let spawner = StandardSpawner::new(
            StandardPeerConfig {
                address: NormalizedAddress::with_hardcoded_dns(
                    "example.com",
                    123,
                    vec!["127.0.0.1:123".parse().unwrap()],
                )
                .into(),
            },
            NETWORK_WAIT_PERIOD,
        );
        let spawner_id = spawner.get_id();
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);
        let (_notify_tx, notify_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        tokio::spawn(async move { spawner.run(action_tx, notify_rx).await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let res = action_rx.try_recv().unwrap();
        assert_eq!(res.id, spawner_id);
        let params = get_create_params(res);
        assert_eq!(params.addr.to_string(), "127.0.0.1:123");

        // and now we should no longer receive anything
        tokio::time::sleep(Duration::from_millis(10)).await;
        let res = action_rx.try_recv().unwrap_err();
        assert_eq!(res, TryRecvError::Empty);
    }

    #[tokio::test]
    async fn recreates_a_peer() {
        let spawner = StandardSpawner::new(
            StandardPeerConfig {
                address: NormalizedAddress::with_hardcoded_dns(
                    "example.com",
                    123,
                    vec!["127.0.0.1:123".parse().unwrap()],
                )
                .into(),
            },
            NETWORK_WAIT_PERIOD,
        );
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);
        let (notify_tx, notify_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        tokio::spawn(async move { spawner.run(action_tx, notify_rx).await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let res = action_rx.try_recv().unwrap();
        let params = get_create_params(res);

        notify_tx
            .send(SystemEvent::peer_removed(
                params.id,
                PeerRemovalReason::NetworkIssue,
            ))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;

        let res = action_rx.try_recv().unwrap();
        let params = get_create_params(res);
        assert_eq!(params.addr.to_string(), "127.0.0.1:123");
    }

    #[tokio::test]
    async fn reresolves_on_unreachable() {
        let address_strings = ["127.0.0.1:123", "127.0.0.2:123", "127.0.0.3:123"];
        let addresses = address_strings.map(|addr| addr.parse().unwrap());

        let spawner = StandardSpawner::new(
            StandardPeerConfig {
                address: NormalizedAddress::with_hardcoded_dns(
                    "europe.pool.ntp.org",
                    123,
                    addresses.to_vec(),
                )
                .into(),
            },
            NETWORK_WAIT_PERIOD,
        );
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);
        let (notify_tx, notify_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        tokio::spawn(async move { spawner.run(action_tx, notify_rx).await });
        let res = action_rx.recv().await.unwrap();
        let params = get_create_params(res);
        let initial_addr = params.addr;

        // We repeat multiple times and check at least one is different to be less
        // sensitive to dns resolver giving the same pool ip.
        let mut seen_addresses = vec![];
        for _ in 0..5 {
            notify_tx
                .send(SystemEvent::peer_removed(
                    params.id,
                    PeerRemovalReason::Unreachable,
                ))
                .await
                .unwrap();
            let res = action_rx.recv().await.unwrap();
            let params = get_create_params(res);
            seen_addresses.push(params.addr);
        }
        let seen_addresses = seen_addresses;

        for addr in seen_addresses.iter() {
            assert!(
                addresses.contains(addr),
                "{:?} should have been drawn from {:?}",
                addr,
                addresses
            );
        }

        assert!(
            seen_addresses.iter().any(|seen| seen != &initial_addr),
            "Re-resolved\n\n\t{:?}\n\n should contain at least one address that isn't the original\n\n\t{:?}",
            seen_addresses,
            initial_addr,
        );
    }

    #[tokio::test]
    async fn works_if_address_does_not_resolve() {
        let spawner = StandardSpawner::new(
            StandardPeerConfig {
                address: NormalizedAddress::with_hardcoded_dns("does.not.resolve", 123, vec![])
                    .into(),
            },
            NETWORK_WAIT_PERIOD,
        );
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);
        let (_notify_tx, notify_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);
        tokio::spawn(async move { spawner.run(action_tx, notify_rx).await });

        tokio::time::sleep(Duration::from_millis(1000)).await;
        let res = action_rx.try_recv().unwrap_err();
        assert_eq!(res, TryRecvError::Empty);
    }
}
