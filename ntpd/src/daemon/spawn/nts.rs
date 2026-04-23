use std::fmt::Display;
use std::ops::Deref;

use ntp_proto::{KeyExchangeClient, NtsClientConfig, NtsError, SourceConfig};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::warn;

use crate::daemon::config::{NormalizedAddress, NtpAddress};
use crate::daemon::dns::resolve_ke;
use crate::daemon::spawn::resolve_single_ntp_server;

use super::super::config::NtsSourceConfig;

use super::{ClockId, SourceRemovedEvent, SpawnAction, SpawnEvent, Spawner, SpawnerId};

pub struct NtsSpawner {
    config: NtsSourceConfig,
    key_exchange_client: KeyExchangeClient,
    source_config: SourceConfig,
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

impl NtsSpawner {
    pub fn new(
        config: NtsSourceConfig,
        source_config: SourceConfig,
    ) -> Result<NtsSpawner, NtsError> {
        let key_exchange_client = KeyExchangeClient::new(&NtsClientConfig {
            certificates: config.certificate_authorities.clone(),
            protocol_version: config.ntp_version,
        })?;

        Ok(NtsSpawner {
            config,
            key_exchange_client,
            source_config,
            id: SpawnerId::new(),
            has_spawned: false,
        })
    }

    // We do resolution and connecting at the same time to deal with problems with either
    // ipv4 or ipv6.
    async fn resolve_and_connect(&mut self) -> Option<(TcpStream, String)> {
        if self.config.enable_srv_resolution {
            match resolve_ke(&self.config.address).await {
                Ok(addrs) => {
                    let mut last_error = None;
                    for addr in addrs {
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
                                .unwrap_or_else(|| self.config.address.server_name.clone()),
                        ));
                    }

                    if let Some(e) = last_error {
                        warn!(error = ?e, "error while attempting key exchange");
                    } else {
                        warn!(
                            "Unresolvable domain name {}",
                            self.config.address.server_name
                        );
                    }
                    None
                }
                Err(e) => {
                    warn!(error=?e, "Error trying to resolve ke server domain name.");
                    None
                }
            }
        } else {
            let io = match TcpStream::connect((
                self.config.address.server_name.as_str(),
                self.config.address.port,
            ))
            .await
            {
                Ok(io) => io,
                Err(e) => {
                    warn!(error = ?e, "error while attempting key exchange");
                    return None;
                }
            };
            Some((io, self.config.address.server_name.clone()))
        }
    }
}

impl Spawner for NtsSpawner {
    type Error = NtsSpawnError;

    async fn try_spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), NtsSpawnError> {
        let Some((io, name)) = self.resolve_and_connect().await else {
            return Ok(());
        };

        match tokio::time::timeout(
            super::NTS_TIMEOUT,
            self.key_exchange_client.exchange_keys(io, name, []),
        )
        .await
        {
            Ok(Ok(ke)) => {
                if let Some(address) = resolve_single_ntp_server(NtpAddress(
                    NormalizedAddress::new_from_parts(ke.remote.as_str(), ke.port),
                ))
                .await
                {
                    action_tx
                        .send(SpawnEvent::new(
                            self.id,
                            SpawnAction::create_ntp(
                                ClockId::new(),
                                address,
                                self.config.address.deref().clone(),
                                ke.protocol_version,
                                self.source_config,
                                Some(ke.nts),
                            ),
                        ))
                        .await?;
                    self.has_spawned = true;
                }
            }
            Ok(Err(e)) => {
                warn!(error = ?e, "error while attempting key exchange");
            }
            Err(_) => {
                warn!("timeout while attempting key exchange");
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ntp_proto::SourceConfig;
    use tokio::{io::AsyncReadExt, net::TcpListener};

    use crate::daemon::{
        config::{NormalizedAddress, NtsKeAddress, NtsSourceConfig},
        spawn::{Spawner, nts::NtsSpawner},
    };

    #[tokio::test]
    async fn direct_name_resolution() {
        let listener = TcpListener::bind("[::]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::task::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 16];
            let _ = socket.read(&mut buf).await.unwrap();
        });

        let mut spawner = NtsSpawner::new(
            NtsSourceConfig {
                address: NtsKeAddress(NormalizedAddress::new_from_parts("localhost", addr.port())),
                enable_srv_resolution: false,
                certificate_authorities: Arc::default(),
                ntp_version: ntp_proto::ProtocolVersion::V4,
            },
            SourceConfig::default(),
        )
        .unwrap();

        let (sender, _receiver) = tokio::sync::mpsc::channel(1);

        assert!(spawner.try_spawn(&sender).await.is_ok());
        assert!(!spawner.is_complete());

        assert!(server.is_finished());
        assert!(server.await.is_ok());
    }

    #[tokio::test]
    async fn allow_srv_direct_name_resolution() {
        let listener = TcpListener::bind("[::]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::task::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 16];
            let _ = socket.read(&mut buf).await.unwrap();
        });

        let mut spawner = NtsSpawner::new(
            NtsSourceConfig {
                address: NtsKeAddress(NormalizedAddress::new_from_parts("localhost.", addr.port())),
                enable_srv_resolution: true,
                certificate_authorities: Arc::default(),
                ntp_version: ntp_proto::ProtocolVersion::V4,
            },
            SourceConfig::default(),
        )
        .unwrap();

        let (sender, _receiver) = tokio::sync::mpsc::channel(1);

        assert!(spawner.try_spawn(&sender).await.is_ok());
        assert!(!spawner.is_complete());

        assert!(server.is_finished());
        assert!(server.await.is_ok());
    }
}
