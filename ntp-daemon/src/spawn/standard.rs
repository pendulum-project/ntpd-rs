use std::net::SocketAddr;

use thiserror::Error;
use tokio::sync::mpsc;
use tracing::warn;

use crate::config::StandardPeerConfig;

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
                match self.config.addr.lookup_host().await {
                    Ok(mut addresses) => match addresses.next() {
                        None => {
                            warn!("Could not resolve peer address, retrying");
                            tokio::time::sleep(self.network_wait_period).await
                        }
                        Some(first) => {
                            break first;
                        }
                    },
                    Err(e) => {
                        warn!(error = ?e, "error while resolving peer address, retrying");
                        tokio::time::sleep(self.network_wait_period).await
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
                SpawnAction::create(PeerId::new(), addr, self.config.addr.clone(), None),
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
        self.config.addr.to_string()
    }

    fn get_description(&self) -> &str {
        "standard"
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::mpsc::{self, error::TryRecvError};

    use crate::{
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
                addr: NormalizedAddress::with_hardcoded_dns(
                    "example.com",
                    123,
                    vec!["127.0.0.1:123".parse().unwrap()],
                ),
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
                addr: NormalizedAddress::with_hardcoded_dns(
                    "example.com",
                    123,
                    vec!["127.0.0.1:123".parse().unwrap()],
                ),
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
    async fn works_if_address_does_not_resolve() {
        let spawner = StandardSpawner::new(
            StandardPeerConfig {
                addr: NormalizedAddress::with_hardcoded_dns("does.not.resolve", 123, vec![]),
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
