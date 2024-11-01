use std::fmt::Display;
use std::{net::SocketAddr, ops::Deref};

use ntp_proto::ProtocolVersion;
use tokio::sync::mpsc;
use tracing::warn;

use super::super::config::StandardSource;

use super::{
    SourceId, SourceRemovalReason, SourceRemovedEvent, SpawnAction, SpawnEvent, Spawner, SpawnerId,
};

pub struct StandardSpawner {
    id: SpawnerId,
    config: StandardSource,
    resolved: Option<SocketAddr>,
    has_spawned: bool,
}

#[derive(Debug)]
pub enum StandardSpawnError {
    SendError(mpsc::error::SendError<SpawnEvent>),
}

impl Display for StandardSpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SendError(e) => write!(f, "Channel send error: {e}"),
        }
    }
}

impl From<mpsc::error::SendError<SpawnEvent>> for StandardSpawnError {
    fn from(value: mpsc::error::SendError<SpawnEvent>) -> Self {
        Self::SendError(value)
    }
}

impl std::error::Error for StandardSpawnError {}

impl StandardSpawner {
    pub fn new(config: StandardSource) -> StandardSpawner {
        StandardSpawner {
            id: SpawnerId::default(),
            config,
            resolved: None,
            has_spawned: false,
        }
    }

    async fn do_resolve(&mut self, force_resolve: bool) -> Option<SocketAddr> {
        if let (false, Some(addr)) = (force_resolve, self.resolved) {
            Some(addr)
        } else {
            match self.config.address.lookup_host().await {
                Ok(mut addresses) => match addresses.next() {
                    None => {
                        warn!("Could not resolve source address, retrying");
                        None
                    }
                    Some(first) => {
                        self.resolved = Some(first);
                        self.resolved
                    }
                },
                Err(e) => {
                    warn!(error = ?e, "error while resolving source address, retrying");
                    None
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl Spawner for StandardSpawner {
    type Error = StandardSpawnError;

    async fn try_spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), StandardSpawnError> {
        let Some(addr) = self.do_resolve(false).await else {
            return Ok(());
        };
        action_tx
            .send(SpawnEvent::new(
                self.id,
                SpawnAction::create(
                    SourceId::new(),
                    addr,
                    self.config.address.deref().clone(),
                    ProtocolVersion::default(),
                    None,
                ),
            ))
            .await?;
        self.has_spawned = true;
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.has_spawned
    }

    async fn handle_source_removed(
        &mut self,
        removed_source: SourceRemovedEvent,
    ) -> Result<(), StandardSpawnError> {
        if removed_source.reason == SourceRemovalReason::Unreachable {
            // force new resolution
            self.resolved = None;
        }
        if removed_source.reason != SourceRemovalReason::Demobilized {
            self.has_spawned = false;
        }
        Ok(())
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
    use tokio::sync::mpsc::{self, error::TryRecvError};

    use crate::daemon::{
        config::{NormalizedAddress, StandardSource},
        spawn::{
            standard::StandardSpawner, tests::get_create_params, SourceRemovalReason,
            SourceRemovedEvent, Spawner,
        },
        system::MESSAGE_BUFFER_SIZE,
    };

    #[tokio::test]
    async fn creates_a_source() {
        let mut spawner = StandardSpawner::new(StandardSource {
            address: NormalizedAddress::with_hardcoded_dns(
                "example.com",
                123,
                vec!["127.0.0.1:123".parse().unwrap()],
            )
            .into(),
        });
        let spawner_id = spawner.get_id();
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        assert!(!spawner.is_complete());
        spawner.try_spawn(&action_tx).await.unwrap();
        let res = action_rx.try_recv().unwrap();
        assert_eq!(res.id, spawner_id);
        let params = get_create_params(res);
        assert_eq!(params.addr.to_string(), "127.0.0.1:123");

        // Should be complete after spawning
        assert!(spawner.is_complete());
    }

    #[tokio::test]
    async fn recreates_a_source() {
        let mut spawner = StandardSpawner::new(StandardSource {
            address: NormalizedAddress::with_hardcoded_dns(
                "example.com",
                123,
                vec!["127.0.0.1:123".parse().unwrap()],
            )
            .into(),
        });
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        assert!(!spawner.is_complete());
        spawner.try_spawn(&action_tx).await.unwrap();
        let res = action_rx.try_recv().unwrap();
        let params = get_create_params(res);
        assert!(spawner.is_complete());

        spawner
            .handle_source_removed(SourceRemovedEvent {
                id: params.id,
                reason: SourceRemovalReason::NetworkIssue,
            })
            .await
            .unwrap();

        assert!(!spawner.is_complete());
        spawner.try_spawn(&action_tx).await.unwrap();
        let res = action_rx.try_recv().unwrap();
        let params = get_create_params(res);
        assert_eq!(params.addr.to_string(), "127.0.0.1:123");
        assert!(spawner.is_complete());
    }

    #[tokio::test]
    async fn reresolves_on_unreachable() {
        let address_strings = ["127.0.0.1:123", "127.0.0.2:123", "127.0.0.3:123"];
        let addresses = address_strings.map(|addr| addr.parse().unwrap());

        let mut spawner = StandardSpawner::new(StandardSource {
            address: NormalizedAddress::with_hardcoded_dns(
                "europe.pool.ntp.org",
                123,
                addresses.to_vec(),
            )
            .into(),
        });
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        assert!(!spawner.is_complete());
        spawner.try_spawn(&action_tx).await.unwrap();
        let res = action_rx.recv().await.unwrap();
        let params = get_create_params(res);
        let initial_addr = params.addr;
        assert!(spawner.is_complete());

        // We repeat multiple times and check at least one is different to be less
        // sensitive to dns resolver giving the same pool ip.
        let mut seen_addresses = vec![];
        for _ in 0..5 {
            spawner
                .handle_source_removed(SourceRemovedEvent {
                    id: params.id,
                    reason: SourceRemovalReason::Unreachable,
                })
                .await
                .unwrap();

            assert!(!spawner.is_complete());
            spawner.try_spawn(&action_tx).await.unwrap();
            let res = action_rx.recv().await.unwrap();
            let params = get_create_params(res);
            seen_addresses.push(params.addr);
            assert!(spawner.is_complete());
        }
        let seen_addresses = seen_addresses;

        for addr in &seen_addresses {
            assert!(
                addresses.contains(addr),
                "{addr:?} should have been drawn from {addresses:?}"
            );
        }

        assert!(
            seen_addresses.iter().any(|seen| seen != &initial_addr),
            "Re-resolved\n\n\t{seen_addresses:?}\n\n should contain at least one address that isn't the original\n\n\t{initial_addr:?}",
        );
    }

    #[tokio::test]
    async fn works_if_address_does_not_resolve() {
        let mut spawner = StandardSpawner::new(StandardSource {
            address: NormalizedAddress::with_hardcoded_dns("does.not.resolve", 123, vec![]).into(),
        });
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        spawner.try_spawn(&action_tx).await.unwrap();

        let res = action_rx.try_recv().unwrap_err();
        assert_eq!(res, TryRecvError::Empty);
    }
}
