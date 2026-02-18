use std::borrow::Cow;
use std::collections::VecDeque;
use std::fmt::Display;
use std::ops::Deref;

use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::warn;

use ntp_proto::{KeyExchangeClient, NtsClientConfig, NtsError, SourceConfig};

use crate::daemon::config::{NormalizedAddress, NtpAddress};
use crate::daemon::dns::{KeResolutionResult, resolve_ke};
use crate::daemon::spawn::resolve_single_ntp_server;

use super::super::config::NtsPoolSourceConfig;

use super::{ClockId, SourceRemovedEvent, SpawnAction, SpawnEvent, Spawner, SpawnerId};

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
    known_resolutions: VecDeque<KeResolutionResult>,
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
        let key_exchange_client = KeyExchangeClient::new(&NtsClientConfig {
            certificates: config.certificate_authorities.clone(),
            protocol_version: config.ntp_version,
        })?;

        Ok(NtsPoolSpawner {
            config,
            key_exchange_client,
            source_config,
            id: SpawnerId::new(),
            current_sources: vec![],
            known_resolutions: VecDeque::new(),
        })
    }

    fn contains_source(&self, domain: &str) -> bool {
        self.current_sources
            .iter()
            .any(|source| source.remote == domain)
    }

    async fn lookup(&mut self) -> Option<(TcpStream, String, Option<String>)> {
        if self.config.enable_srv_resolution {
            let mut did_resolution = false;
            loop {
                if self.known_resolutions.is_empty() {
                    if did_resolution {
                        warn!(
                            "Could not find more sources for pool at {}",
                            self.config.addr.server_name
                        );
                        return None;
                    }
                    did_resolution = true;
                    match resolve_ke(&self.config.addr).await {
                        Ok(resolutions) => self.known_resolutions.extend(resolutions),
                        Err(e) => {
                            warn!(error=?e, "Error trying to resolve ke server domain name.");
                            return None;
                        }
                    }

                    if self.known_resolutions.is_empty() {
                        warn!("Unresolvable domain name {}", self.config.addr.server_name);
                        return None;
                    }
                }

                let mut last_error = None;
                while let Some(addr) = self.known_resolutions.pop_front() {
                    if let Some(name) = &addr.srv_record_name
                        && self.contains_source(name)
                    {
                        continue;
                    }
                    let io = match TcpStream::connect(addr.addr).await {
                        Ok(io) => io,
                        Err(e) => {
                            last_error = Some(e);
                            continue;
                        }
                    };
                    return Some((
                        io,
                        addr.srv_record_name
                            .clone()
                            .unwrap_or_else(|| self.config.addr.server_name.clone()),
                        addr.srv_record_name,
                    ));
                }

                if let Some(e) = last_error {
                    warn!(error = ?e, "error while attempting key exchange");
                    return None;
                }
            }
        } else {
            let io = match TcpStream::connect((
                self.config.addr.server_name.as_str(),
                self.config.addr.port,
            ))
            .await
            {
                Ok(io) => io,
                Err(e) => {
                    warn!(error = ?e, "error while attempting key exchange");
                    return None;
                }
            };
            Some((io, self.config.addr.server_name.clone(), None))
        }
    }
}

impl Spawner for NtsPoolSpawner {
    type Error = NtsPoolSpawnError;

    async fn try_spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), NtsPoolSpawnError> {
        for _ in 0..self.config.count.saturating_sub(self.current_sources.len()) {
            let Some((io, name, remote_name)) = self.lookup().await else {
                return Ok(());
            };

            match tokio::time::timeout(
                super::NTS_TIMEOUT,
                self.key_exchange_client.exchange_keys(
                    io,
                    name,
                    self.current_sources
                        .iter()
                        .map(|source| Cow::Borrowed(source.remote.as_str())),
                ),
            )
            .await
            {
                Ok(Ok(ke))
                    if !self.contains_source(remote_name.as_deref().unwrap_or(&ke.remote)) =>
                {
                    if let Some(address) = resolve_single_ntp_server(NtpAddress(
                        NormalizedAddress::new_from_parts(ke.remote.as_str(), ke.port),
                    ))
                    .await
                    {
                        let id = ClockId::new();
                        self.current_sources.push(PoolSource {
                            id,
                            remote: remote_name.unwrap_or(ke.remote),
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
