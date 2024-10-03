use std::fmt::Display;
use std::ops::Deref;

use tokio::sync::mpsc;
use tracing::warn;

use super::super::{
    config::NtsPoolSourceConfig, keyexchange::key_exchange_client_with_denied_servers,
};

use super::{SourceId, SourceRemovedEvent, SpawnAction, SpawnEvent, Spawner, SpawnerId};

use super::nts::resolve_addr;

struct PoolSource {
    id: SourceId,
    remote: String,
}

pub struct NtsPoolSpawner {
    config: NtsPoolSourceConfig,
    id: SpawnerId,
    current_sources: Vec<PoolSource>,
}

#[derive(Debug)]
pub enum NtsPoolSpawnError {
    SendError(mpsc::error::SendError<SpawnEvent>),
}

impl std::error::Error for NtsPoolSpawnError {}

impl Display for NtsPoolSpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SendError(e) => write!(f, "Channel send error: {e}"),
        }
    }
}

impl From<mpsc::error::SendError<SpawnEvent>> for NtsPoolSpawnError {
    fn from(value: mpsc::error::SendError<SpawnEvent>) -> Self {
        Self::SendError(value)
    }
}

impl NtsPoolSpawner {
    pub fn new(config: NtsPoolSourceConfig) -> NtsPoolSpawner {
        NtsPoolSpawner {
            config,
            id: Default::default(),
            current_sources: Default::default(),
            //known_ips: Default::default(),
        }
    }

    fn contains_source(&self, domain: &str) -> bool {
        self.current_sources
            .iter()
            .any(|source| source.remote == domain)
    }
}

#[async_trait::async_trait]
impl Spawner for NtsPoolSpawner {
    type Error = NtsPoolSpawnError;

    async fn try_spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), NtsPoolSpawnError> {
        for _ in 0..self.config.count.saturating_sub(self.current_sources.len()) {
            match key_exchange_client_with_denied_servers(
                self.config.addr.server_name.clone(),
                self.config.addr.port,
                &self.config.certificate_authorities,
                #[cfg(feature = "unstable_ntpv5")]
                self.config.ntp_version,
                #[cfg(not(feature = "unstable_ntpv5"))]
                None,
                self.current_sources
                    .iter()
                    .map(|source| source.remote.clone()),
            )
            .await
            {
                Ok(ke) if !self.contains_source(&ke.remote) => {
                    if let Some(address) = resolve_addr((ke.remote.as_str(), ke.port)).await {
                        let id = SourceId::new();
                        self.current_sources.push(PoolSource {
                            id,
                            remote: ke.remote,
                        });
                        action_tx
                            .send(SpawnEvent::new(
                                self.id,
                                SpawnAction::create_ntp(
                                    id,
                                    address,
                                    self.config.addr.deref().clone(),
                                    ke.protocol_version,
                                    Some(ke.nts),
                                ),
                            ))
                            .await?;
                    }
                }
                Ok(_) => {
                    warn!("received an address from pool-ke that we already had, ignoring");
                    continue;
                }
                Err(e) => {
                    warn!(error = ?e, "error while attempting key exchange");
                    break;
                }
            };
        }

        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.current_sources.len() >= self.config.count
    }

    async fn handle_source_removed(
        &mut self,
        removed_source: SourceRemovedEvent,
    ) -> Result<(), NtsPoolSpawnError> {
        self.current_sources.retain(|p| p.id != removed_source.id);
        Ok(())
    }

    fn get_id(&self) -> SpawnerId {
        self.id
    }

    fn get_addr_description(&self) -> String {
        format!("{} ({})", self.config.addr.deref(), self.config.count)
    }

    fn get_description(&self) -> &str {
        "nts-pool"
    }
}
