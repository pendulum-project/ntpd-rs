use std::{net::SocketAddr, ops::Deref};

use thiserror::Error;
use tokio::sync::mpsc;
use tracing::warn;

use crate::{config::PoolPeerConfig, spawn::SpawnAction};

use super::{BasicSpawner, PeerId, PeerRemovedEvent, SpawnEvent, SpawnerId};

struct PoolPeer {
    id: PeerId,
    addr: SocketAddr,
}

pub struct PoolSpawner {
    config: PoolPeerConfig,
    network_wait_period: std::time::Duration,
    id: SpawnerId,
    current_peers: Vec<PoolPeer>,
    known_ips: Vec<SocketAddr>,
}

#[derive(Error, Debug)]
pub enum PoolSpawnError {}

impl PoolSpawner {
    pub fn new(config: PoolPeerConfig, network_wait_period: std::time::Duration) -> PoolSpawner {
        PoolSpawner {
            config,
            network_wait_period,
            id: Default::default(),
            current_peers: Default::default(),
            known_ips: Default::default(),
        }
    }

    pub async fn fill_pool(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), PoolSpawnError> {
        let mut wait_period = self.network_wait_period;

        // early return if there is nothing to do
        if self.current_peers.len() >= self.config.max_peers {
            return Ok(());
        }

        loop {
            if self.known_ips.len() < self.config.max_peers - self.current_peers.len() {
                match self.config.addr.lookup_host().await {
                    Ok(addresses) => {
                        // add the addresses looked up to our list of known ips
                        self.known_ips.append(&mut addresses.collect());
                        // remove known ips that we are already connected to
                        self.known_ips
                            .retain(|ip| !self.current_peers.iter().any(|p| p.addr == *ip));
                    }
                    Err(e) => {
                        warn!(error = ?e, "error while resolving peer address, retrying");
                        tokio::time::sleep(wait_period).await;
                        continue;
                    }
                }
            }

            // Try and add peers to our pool
            while self.current_peers.len() < self.config.max_peers {
                if let Some(addr) = self.known_ips.pop() {
                    let id = PeerId::new();
                    self.current_peers.push(PoolPeer { id, addr });
                    let action =
                        SpawnAction::create(id, addr, self.config.addr.deref().clone(), None);
                    tracing::debug!(?action, "intending to spawn new pool peer at");

                    action_tx
                        .send(SpawnEvent::new(self.id, action))
                        .await
                        .expect("Channel was no longer connected");
                } else {
                    break;
                }
            }

            let wait_period_max = if cfg!(test) {
                std::time::Duration::default()
            } else {
                std::time::Duration::from_secs(60)
            };

            wait_period = Ord::min(2 * wait_period, wait_period_max);
            let peers_needed = self.config.max_peers - self.current_peers.len();
            if peers_needed > 0 {
                warn!(peers_needed, "could not fully fill pool");
                tokio::time::sleep(wait_period).await;
            } else {
                return Ok(());
            }
        }
    }
}

#[async_trait::async_trait]
impl BasicSpawner for PoolSpawner {
    type Error = PoolSpawnError;

    async fn handle_init(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), PoolSpawnError> {
        self.fill_pool(action_tx).await?;
        Ok(())
    }

    async fn handle_peer_removed(
        &mut self,
        removed_peer: PeerRemovedEvent,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), PoolSpawnError> {
        self.current_peers.retain(|p| p.id != removed_peer.id);
        self.fill_pool(action_tx).await?;
        Ok(())
    }

    fn get_id(&self) -> SpawnerId {
        self.id
    }

    fn get_addr_description(&self) -> String {
        format!("{} ({})", self.config.addr.deref(), self.config.max_peers)
    }

    fn get_description(&self) -> &str {
        "pool"
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::mpsc::{self, error::TryRecvError};

    use crate::{
        config::{NormalizedAddress, PoolPeerConfig},
        spawn::{
            pool::PoolSpawner, tests::get_create_params, PeerRemovalReason, Spawner, SystemEvent,
        },
        system::{MESSAGE_BUFFER_SIZE, NETWORK_WAIT_PERIOD},
    };

    #[tokio::test]
    async fn creates_multiple_peers() {
        let address_strings = ["127.0.0.1:123", "127.0.0.2:123", "127.0.0.3:123"];
        let addresses = address_strings.map(|addr| addr.parse().unwrap());

        let pool = PoolSpawner::new(
            PoolPeerConfig {
                addr: NormalizedAddress::with_hardcoded_dns("example.com", 123, addresses.to_vec())
                    .into(),
                max_peers: 2,
            },
            NETWORK_WAIT_PERIOD,
        );
        let spawner_id = pool.get_id();
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);
        let (_notify_tx, notify_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);
        tokio::spawn(async move { pool.run(action_tx, notify_rx).await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let res = action_rx.try_recv().unwrap();
        assert_eq!(spawner_id, res.id);
        let params = get_create_params(res);
        let addr1 = params.addr;

        tokio::time::sleep(Duration::from_millis(10)).await;
        let res = action_rx.try_recv().unwrap();
        assert_eq!(spawner_id, res.id);
        let params = get_create_params(res);
        let addr2 = params.addr;

        assert_ne!(addr1, addr2);
        assert!(addresses.contains(&addr1));
        assert!(addresses.contains(&addr2));

        tokio::time::sleep(Duration::from_millis(10)).await;
        let res = action_rx.try_recv().unwrap_err();
        assert_eq!(res, TryRecvError::Empty);
    }

    #[tokio::test]
    async fn refills_peers_upto_limit() {
        let address_strings = ["127.0.0.1:123", "127.0.0.2:123", "127.0.0.3:123"];
        let addresses = address_strings.map(|addr| addr.parse().unwrap());

        let pool = PoolSpawner::new(
            PoolPeerConfig {
                addr: NormalizedAddress::with_hardcoded_dns("example.com", 123, addresses.to_vec())
                    .into(),
                max_peers: 2,
            },
            NETWORK_WAIT_PERIOD,
        );
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);
        let (notify_tx, notify_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);
        tokio::spawn(async move { pool.run(action_tx, notify_rx).await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let res = action_rx.try_recv().unwrap();
        let params = get_create_params(res);
        let addr1 = params.addr;
        tokio::time::sleep(Duration::from_millis(10)).await;
        let res = action_rx.try_recv().unwrap();
        let params = get_create_params(res);
        let addr2 = params.addr;
        tokio::time::sleep(Duration::from_millis(10)).await;

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
        let addr3 = params.addr;

        // no duplicates!
        assert_ne!(addr1, addr2);
        assert_ne!(addr2, addr3);
        assert_ne!(addr3, addr1);

        assert!(addresses.contains(&addr3));
    }

    #[tokio::test]
    async fn works_if_address_does_not_resolve() {
        let pool = PoolSpawner::new(
            PoolPeerConfig {
                addr: NormalizedAddress::with_hardcoded_dns("does.not.resolve", 123, vec![]).into(),
                max_peers: 2,
            },
            NETWORK_WAIT_PERIOD,
        );
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);
        let (_notify_tx, notify_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);
        tokio::spawn(async move { pool.run(action_tx, notify_rx).await });
        tokio::time::sleep(Duration::from_millis(1000)).await;
        let res = action_rx.try_recv().unwrap_err();
        assert_eq!(res, TryRecvError::Empty);
    }
}
