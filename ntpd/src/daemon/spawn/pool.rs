use std::fmt::Display;
use std::{net::SocketAddr, ops::Deref};

use ntp_proto::ProtocolVersion;
use tokio::sync::mpsc;
use tracing::warn;

use super::super::config::PoolSourceConfig;

use super::{SourceId, SourceRemovedEvent, SpawnAction, SpawnEvent, Spawner, SpawnerId};

struct PoolSource {
    id: SourceId,
    addr: SocketAddr,
}

pub struct PoolSpawner {
    config: PoolSourceConfig,
    id: SpawnerId,
    current_sources: Vec<PoolSource>,
    known_ips: Vec<SocketAddr>,
}

#[derive(Debug)]
pub enum PoolSpawnError {}

impl Display for PoolSpawnError {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unreachable!()
    }
}

impl std::error::Error for PoolSpawnError {}

impl PoolSpawner {
    pub fn new(config: PoolSourceConfig) -> PoolSpawner {
        PoolSpawner {
            config,
            id: SpawnerId::default(),
            current_sources: Vec::default(),
            known_ips: Vec::default(),
        }
    }
}

#[async_trait::async_trait]
impl Spawner for PoolSpawner {
    type Error = PoolSpawnError;

    async fn try_spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), PoolSpawnError> {
        // early return if there is nothing to do
        if self.current_sources.len() >= self.config.count {
            return Ok(());
        }

        if self.known_ips.len() < self.config.count - self.current_sources.len() {
            match self.config.addr.lookup_host().await {
                Ok(addresses) => {
                    // add the addresses looked up to our list of known ips
                    self.known_ips.append(&mut addresses.collect());
                    // remove known ips that we are already connected to or that we want to ignore
                    self.known_ips.retain(|ip| {
                        !self.current_sources.iter().any(|p| p.addr == *ip)
                            && !self.config.ignore.iter().any(|ign| *ign == ip.ip())
                    });
                }
                Err(e) => {
                    warn!(error = ?e, "error while resolving source address, retrying");
                    return Ok(());
                }
            }
        }

        // Try and add sources to our pool
        while self.current_sources.len() < self.config.count {
            if let Some(addr) = self.known_ips.pop() {
                let id = SourceId::new();
                self.current_sources.push(PoolSource { id, addr });
                let action = SpawnAction::create(
                    id,
                    addr,
                    self.config.addr.deref().clone(),
                    ProtocolVersion::default(),
                    None,
                );
                tracing::debug!(?action, "intending to spawn new pool source at");

                action_tx
                    .send(SpawnEvent::new(self.id, action))
                    .await
                    .expect("Channel was no longer connected");
            } else {
                break;
            }
        }

        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.current_sources.len() >= self.config.count
    }

    async fn handle_source_removed(
        &mut self,
        removed_source: SourceRemovedEvent,
    ) -> Result<(), PoolSpawnError> {
        self.current_sources.retain(|p| p.id != removed_source.id);
        Ok(())
    }

    fn get_id(&self) -> SpawnerId {
        self.id
    }

    fn get_addr_description(&self) -> String {
        format!("{} ({})", &*self.config.addr, self.config.count)
    }

    fn get_description(&self) -> &str {
        "pool"
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc::{self, error::TryRecvError};

    use crate::daemon::{
        config::{NormalizedAddress, PoolSourceConfig},
        spawn::{
            pool::PoolSpawner, tests::get_create_params, SourceRemovalReason, SourceRemovedEvent,
            Spawner,
        },
        system::MESSAGE_BUFFER_SIZE,
    };

    #[tokio::test]
    async fn creates_multiple_sources() {
        let address_strings = ["127.0.0.1:123", "127.0.0.2:123", "127.0.0.3:123"];
        let addresses = address_strings.map(|addr| addr.parse().unwrap());

        let mut pool = PoolSpawner::new(PoolSourceConfig {
            addr: NormalizedAddress::with_hardcoded_dns("example.com", 123, addresses.to_vec())
                .into(),
            count: 2,
            ignore: vec![],
        });
        let spawner_id = pool.get_id();
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        assert!(!pool.is_complete());
        pool.try_spawn(&action_tx).await.unwrap();
        let res = action_rx.try_recv().unwrap();
        assert_eq!(spawner_id, res.id);
        let params = get_create_params(res);
        let addr1 = params.addr;

        let res = action_rx.try_recv().unwrap();
        assert_eq!(spawner_id, res.id);
        let params = get_create_params(res);
        let addr2 = params.addr;

        assert_ne!(addr1, addr2);
        assert!(addresses.contains(&addr1));
        assert!(addresses.contains(&addr2));

        let res = action_rx.try_recv().unwrap_err();
        assert_eq!(res, TryRecvError::Empty);
        assert!(pool.is_complete());
    }

    #[tokio::test]
    async fn respect_ignores() {
        let address_strings = ["127.0.0.1:123", "127.0.0.2:123", "127.0.0.3:123"];
        let addresses = address_strings.map(|addr| addr.parse().unwrap());
        let ignores = vec!["127.0.0.1".parse().unwrap()];

        let mut pool = PoolSpawner::new(PoolSourceConfig {
            addr: NormalizedAddress::with_hardcoded_dns("example.com", 123, addresses.to_vec())
                .into(),
            count: 2,
            ignore: ignores.clone(),
        });
        let spawner_id = pool.get_id();
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        assert!(!pool.is_complete());
        pool.try_spawn(&action_tx).await.unwrap();
        let res = action_rx.try_recv().unwrap();
        assert_eq!(spawner_id, res.id);
        let params = get_create_params(res);
        let addr1 = params.addr;

        let res = action_rx.try_recv().unwrap();
        assert_eq!(spawner_id, res.id);
        let params = get_create_params(res);
        let addr2 = params.addr;

        assert_ne!(addr1, addr2);
        assert!(addresses.contains(&addr1));
        assert!(addresses.contains(&addr2));
        assert!(!ignores.contains(&addr1.ip()));
        assert!(!ignores.contains(&addr2.ip()));

        let res = action_rx.try_recv().unwrap_err();
        assert_eq!(res, TryRecvError::Empty);
        assert!(pool.is_complete());
    }

    #[tokio::test]
    async fn refills_sources_upto_limit() {
        let address_strings = ["127.0.0.1:123", "127.0.0.2:123", "127.0.0.3:123"];
        let addresses = address_strings.map(|addr| addr.parse().unwrap());

        let mut pool = PoolSpawner::new(PoolSourceConfig {
            addr: NormalizedAddress::with_hardcoded_dns("example.com", 123, addresses.to_vec())
                .into(),
            count: 2,
            ignore: vec![],
        });
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        assert!(!pool.is_complete());
        pool.try_spawn(&action_tx).await.unwrap();
        let res = action_rx.try_recv().unwrap();
        let params = get_create_params(res);
        let addr1 = params.addr;
        let res = action_rx.try_recv().unwrap();
        let params = get_create_params(res);
        let addr2 = params.addr;
        assert!(pool.is_complete());

        pool.handle_source_removed(SourceRemovedEvent {
            id: params.id,
            reason: SourceRemovalReason::NetworkIssue,
        })
        .await
        .unwrap();

        assert!(!pool.is_complete());
        pool.try_spawn(&action_tx).await.unwrap();
        let res = action_rx.try_recv().unwrap();
        let params = get_create_params(res);
        let addr3 = params.addr;

        // no duplicates!
        assert_ne!(addr1, addr2);
        assert_ne!(addr2, addr3);
        assert_ne!(addr3, addr1);

        assert!(addresses.contains(&addr3));
        assert!(pool.is_complete());
    }

    #[tokio::test]
    async fn works_if_address_does_not_resolve() {
        let mut pool = PoolSpawner::new(PoolSourceConfig {
            addr: NormalizedAddress::with_hardcoded_dns("does.not.resolve", 123, vec![]).into(),
            count: 2,
            ignore: vec![],
        });
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);
        assert!(!pool.is_complete());
        pool.try_spawn(&action_tx).await.unwrap();
        let res = action_rx.try_recv().unwrap_err();
        assert_eq!(res, TryRecvError::Empty);
        assert!(!pool.is_complete());
    }
}
