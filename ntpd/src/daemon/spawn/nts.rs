use std::fmt::Display;
use std::net::SocketAddr;
use std::ops::Deref;

use tokio::sync::mpsc;
use tracing::warn;

use super::super::{config::NtsSourceConfig, keyexchange::key_exchange_client};

use super::{SourceId, SourceRemovedEvent, SpawnAction, SpawnEvent, Spawner, SpawnerId};

pub struct NtsSpawner {
    config: NtsSourceConfig,
    id: SpawnerId,
    has_spawned: bool,
}

#[derive(Debug)]
pub enum NtsSpawnError {
    SendError(mpsc::error::SendError<SpawnEvent>),
}

impl std::error::Error for NtsSpawnError {}

impl Display for NtsSpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SendError(e) => write!(f, "Channel send error: {e}"),
        }
    }
}

impl From<mpsc::error::SendError<SpawnEvent>> for NtsSpawnError {
    fn from(value: mpsc::error::SendError<SpawnEvent>) -> Self {
        Self::SendError(value)
    }
}

pub(super) async fn resolve_addr(address: (&str, u16)) -> Option<SocketAddr> {
    match tokio::net::lookup_host(address).await {
        Ok(mut addresses) => match addresses.next() {
            Some(address) => Some(address),
            None => {
                warn!("received unknown domain name from NTS-ke");
                None
            }
        },
        Err(e) => {
            warn!(error = ?e, "error while resolving source address, retrying");
            None
        }
    }
}

impl NtsSpawner {
    pub fn new(config: NtsSourceConfig) -> NtsSpawner {
        NtsSpawner {
            config,
            id: Default::default(),
            has_spawned: false,
        }
    }
}

#[async_trait::async_trait]
impl Spawner for NtsSpawner {
    type Error = NtsSpawnError;

    async fn try_spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), NtsSpawnError> {
        match key_exchange_client(
            self.config.address.server_name.clone(),
            self.config.address.port,
            &self.config.certificate_authorities,
            #[cfg(feature = "unstable_ntpv5")]
            self.config.ntp_version,
            #[cfg(not(feature = "unstable_ntpv5"))]
            None,
        )
        .await
        {
            Ok(ke) => {
                if let Some(address) = resolve_addr((ke.remote.as_str(), ke.port)).await {
                    action_tx
                        .send(SpawnEvent::new(
                            self.id,
                            SpawnAction::create_ntp(
                                SourceId::new(),
                                address,
                                self.config.address.deref().clone(),
                                ke.protocol_version,
                                Some(ke.nts),
                            ),
                        ))
                        .await?;
                    self.has_spawned = true;
                }
            }
            Err(e) => {
                warn!(error = ?e, "error while attempting key exchange");
            }
        }

        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.has_spawned
    }

    async fn handle_source_removed(
        &mut self,
        _removed_source: SourceRemovedEvent,
    ) -> Result<(), NtsSpawnError> {
        self.has_spawned = false;
        Ok(())
    }

    fn get_id(&self) -> SpawnerId {
        self.id
    }

    fn get_addr_description(&self) -> String {
        self.config.address.to_string()
    }

    fn get_description(&self) -> &str {
        "nts"
    }
}
