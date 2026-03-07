use std::borrow::Cow;
use std::fmt::Display;
use std::ops::Deref;

use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::warn;

use ntp_proto::{KeyExchangeClient, NtsClientConfig, NtsError, SourceConfig};

use super::super::config::NtsPoolSourceConfig;

use super::{ClockId, SourceRemovedEvent, SpawnAction, SpawnEvent, Spawner, SpawnerId};

use super::nts::resolve_addr;

struct PoolSource {
    id: ClockId,
    remote: String,
}

pub struct NtsPoolSpawner {
    config: NtsPoolSourceConfig,
    key_exchange_client: KeyExchangeClient,
    source_config: SourceConfig,
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
    pub fn new(
        config: NtsPoolSourceConfig,
        source_config: SourceConfig,
    ) -> Result<NtsPoolSpawner, NtsError> {
        let key_exchange_client = KeyExchangeClient::new(NtsClientConfig {
            certificates: config.certificate_authorities.clone(),
            protocol_version: config.ntp_version,
        })?;

        Ok(NtsPoolSpawner {
            config,
            key_exchange_client,
            source_config,
            id: SpawnerId::new(),
            current_sources: vec![],
        })
    }

    fn contains_source(&self, domain: &str) -> bool {
        self.current_sources
            .iter()
            .any(|source| source.remote == domain)
    }
}

impl Spawner for NtsPoolSpawner {
    type Error = NtsPoolSpawnError;

    async fn try_spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), NtsPoolSpawnError> {
        for _ in 0..self.config.count.saturating_sub(self.current_sources.len()) {
            let io = match TcpStream::connect((
                self.config.addr.server_name.as_str(),
                self.config.addr.port,
            ))
            .await
            {
                Ok(io) => io,
                Err(e) => {
                    warn!(error = ?e, "error while attempting key exchange");
                    break;
                }
            };

            match tokio::time::timeout(
                super::NTS_TIMEOUT,
                self.key_exchange_client.exchange_keys(
                    io,
                    self.config.addr.server_name.clone(),
                    self.current_sources
                        .iter()
                        .map(|source| Cow::Borrowed(source.remote.as_str())),
                ),
            )
            .await
            {
                Ok(Ok(ke)) if !self.contains_source(&ke.remote) => {
                    if let Some(address) = resolve_addr((ke.remote.as_str(), ke.port)).await {
                        let id = ClockId::new();
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
                                    self.source_config,
                                    Some(ke.nts),
                                ),
                            ))
                            .await?;
                    }
                }
                Ok(Ok(_)) => {
                    warn!("received an address from pool-ke that we already had, ignoring");
                    continue;
                }
                Ok(Err(e)) => {
                    warn!(error = ?e, "error while attempting key exchange");
                    break;
                }
                Err(_) => {
                    warn!("timeout while attempting key exchange");
                }
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
