use std::fmt::Display;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use ntp_proto::{
    KeyExchangeClient, NtsClientConfig, NtsError, SourceConfig, tls_utils::Certificate,
};
use ntp_proto::{PollIntervalLimits, ProtocolVersion};
use statime_algo::LinkConfig;
use statime_base::{Link, SourceType, StdController};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::warn;

use crate::daemon::dns::resolve_ke;
use crate::daemon::ntp_source::SourceTask;
use crate::daemon::spawn::{
    CreationParameters, LinkTerminationReason, NormalizedAddress, NtpAddress, NtsKeAddress,
    SpawnFailureReason, resolve_single_ntp_server,
};

use super::{ClockId, Spawner, SpawnerId};

#[derive(Debug, Clone, PartialEq)]
pub struct NtpNtsSpawnerConfig {
    pub address: NtsKeAddress,
    pub certificate_authorities: Arc<[Certificate]>,
    pub enable_srv_resolution: bool,
    pub ntp_version: ProtocolVersion,
    pub poll_interval_limits: PollIntervalLimits,
    pub desired_error_bound: statime_base::Duration,
    pub delay_decay_rate: f64,
}

pub struct NtpNtsSpawner {
    config: NtpNtsSpawnerConfig,
    key_exchange_client: Arc<KeyExchangeClient>,
    state: Arc<Mutex<NtsNtpSpawnerState>>,
}

#[derive(Default)]
struct NtsNtpSpawnerState {
    has_spawned: bool,
}

impl NtpNtsSpawner {
    pub fn new(config: NtpNtsSpawnerConfig) -> Result<NtpNtsSpawner, NtsError> {
        let key_exchange_client = Arc::new(KeyExchangeClient::new(&NtsClientConfig {
            certificates: config.certificate_authorities.clone(),
            protocol_version: config.ntp_version,
        })?);

        Ok(NtpNtsSpawner {
            config,
            key_exchange_client,
            state: Arc::default(),
        })
    }

    // We do resolution and connecting at the same time to deal with problems with either
    // ipv4 or ipv6.
    async fn resolve_and_connect(
        config: &NtpNtsSpawnerConfig,
    ) -> Result<(TcpStream, String), SpawnFailureReason> {
        if config.enable_srv_resolution {
            match resolve_ke(&config.address).await {
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
                        return Ok((
                            io,
                            addr.srv_record_name
                                .unwrap_or_else(|| config.address.server_name.clone()),
                        ));
                    }

                    if let Some(e) = last_error {
                        warn!(error = ?e, "error while attempting key exchange");
                        Err(SpawnFailureReason::NetworkIssue)
                    } else {
                        warn!("Unresolvable domain name {}", config.address.server_name);
                        Err(SpawnFailureReason::RetryableFailure)
                    }
                }
                Err(e) => {
                    warn!(error=?e, "Error trying to resolve ke server domain name.");
                    Err(SpawnFailureReason::NetworkIssue)
                }
            }
        } else {
            let io = match TcpStream::connect((
                config.address.server_name.as_str(),
                config.address.port,
            ))
            .await
            {
                Ok(io) => io,
                Err(e) => {
                    warn!(error = ?e, "error while attempting key exchange");
                    return Err(SpawnFailureReason::NetworkIssue);
                }
            };
            Ok((io, config.address.server_name.clone()))
        }
    }
}

impl<TimeController: StdController> Spawner<TimeController> for NtpNtsSpawner
where
    TimeController::LinkConfig: From<statime_algo::LinkConfig>,
    TimeController::TrackedLinkConfig: From<statime_algo::TrackedLinkConfig>,
    TimeController::Link<Arc<TimeController>>: Send + 'static,
{
    fn try_spawn(&mut self) -> super::TrySpawnFuture<TimeController> {
        let state = self.state.clone();
        let config = self.config.clone();
        let key_exchange_client = self.key_exchange_client.clone();

        Box::new(async move {
            let (io, name) = Self::resolve_and_connect(&config).await?;

            match tokio::time::timeout(
                super::NTS_TIMEOUT,
                key_exchange_client.exchange_keys(io, name, []),
            )
            .await
            {
                Ok(Ok(ke)) => {
                    if let Some(address) = resolve_single_ntp_server(NtpAddress(
                        NormalizedAddress::new_from_parts(ke.remote.as_str(), ke.port),
                    ))
                    .await
                    {
                        Ok(CreationParameters {
                            stype: SourceType::Ntp,
                            link_config: LinkConfig {
                                desired_error_bound: config.desired_error_bound,
                                period: None,
                            }
                            .into(),
                            tracked_link_config: Some(
                                statime_algo::TrackedLinkConfig {
                                    decay_rate: config.delay_decay_rate,
                                    longest_interval_for_delay_estimation:
                                        statime_base::Duration::from_seconds_nanos(1, 0),
                                }
                                .into(),
                            ),
                            creator: Box::new(
                                move |controller: TimeController::Link<Arc<TimeController>>,
                                      clock,
                                      managers| {
                                    let link_id = controller.id();
                                    let (source, initial_actions) =
                                        managers.ntp_manager().new_source(
                                            address,
                                            SourceConfig {
                                                poll_interval_limits: config.poll_interval_limits,
                                                initial_poll_interval: config
                                                    .poll_interval_limits
                                                    .min,
                                            },
                                            config.ntp_version,
                                            controller,
                                            None,
                                        );

                                    state.lock().unwrap().has_spawned = true;

                                    SourceTask::spawn(
                                        link_id,
                                        config.address.to_string(),
                                        address,
                                        clock,
                                        source,
                                        initial_actions,
                                    )
                                },
                            ),
                        })
                    } else {
                        Err(SpawnFailureReason::RetryableFailure)
                    }
                }
                Ok(Err(e)) => {
                    warn!(error = ?e, "error while attempting key exchange");
                    Err(SpawnFailureReason::RetryableFailure)
                }
                Err(_) => {
                    warn!("timeout while attempting key exchange");
                    Err(SpawnFailureReason::RetryableFailure)
                }
            }
        })
    }

    fn needs_spawn(&self) -> bool {
        !self.state.lock().unwrap().has_spawned
    }

    fn source_terminated(
        &mut self,
        id: statime_base::LinkId,
        reason: super::LinkTerminationReason,
    ) {
        if reason != LinkTerminationReason::MustDemobilize {
            let mut state = self.state.lock().unwrap();
            state.has_spawned = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ntp_proto::{PollIntervalLimits, SourceConfig};
    use statime_algo::{KalmanController, StdKalmanStorage};
    use tokio::{io::AsyncReadExt, net::TcpListener};

    use crate::daemon::{
        clock::NtpClockWrapper,
        spawn::{
            NormalizedAddress, NtsKeAddress, Spawner,
            ntp_nts::{NtpNtsSpawner, NtpNtsSpawnerConfig},
        },
    };

    #[tokio::test]
    async fn direct_name_resolution() {
        #[cfg(feature = "openssl")]
        let _ = rustls_openssl::default_provider().install_default();

        let listener = TcpListener::bind("[::]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::task::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 16];
            let _ = socket.read(&mut buf).await.unwrap();
        });

        let mut spawner = NtpNtsSpawner::new(NtpNtsSpawnerConfig {
            address: NtsKeAddress(NormalizedAddress::new_from_parts("localhost", addr.port())),
            enable_srv_resolution: false,
            certificate_authorities: Arc::default(),
            ntp_version: ntp_proto::ProtocolVersion::V4,
            poll_interval_limits: PollIntervalLimits::default(),
            desired_error_bound: statime_base::Duration::from_seconds_nanos(0, 1_000_000),
            delay_decay_rate: 1. / 86400f64.sqrt(),
        })
        .unwrap();

        assert!(
            Box::into_pin(Spawner::<
                KalmanController<StdKalmanStorage<NtpClockWrapper>, NtpClockWrapper>,
            >::try_spawn(&mut spawner))
            .await
            .is_err()
        );
        assert!(Spawner::<
            KalmanController<StdKalmanStorage<NtpClockWrapper>, NtpClockWrapper>,
        >::needs_spawn(&spawner));
        assert!(server.is_finished());
        assert!(server.await.is_ok());
    }

    #[tokio::test]
    async fn allow_srv_direct_name_resolution() {
        #[cfg(feature = "openssl")]
        let _ = rustls_openssl::default_provider().install_default();

        let listener = TcpListener::bind("[::]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::task::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 16];
            let _ = socket.read(&mut buf).await.unwrap();
        });

        let mut spawner = NtpNtsSpawner::new(NtpNtsSpawnerConfig {
            address: NtsKeAddress(NormalizedAddress::new_from_parts("localhost", addr.port())),
            enable_srv_resolution: true,
            certificate_authorities: Arc::default(),
            ntp_version: ntp_proto::ProtocolVersion::V4,
            poll_interval_limits: PollIntervalLimits::default(),
            desired_error_bound: statime_base::Duration::from_seconds_nanos(0, 1_000_000),
            delay_decay_rate: 1. / 86400f64.sqrt(),
        })
        .unwrap();

        assert!(
            Box::into_pin(Spawner::<
                KalmanController<StdKalmanStorage<NtpClockWrapper>, NtpClockWrapper>,
            >::try_spawn(&mut spawner))
            .await
            .is_err()
        );
        assert!(Spawner::<
            KalmanController<StdKalmanStorage<NtpClockWrapper>, NtpClockWrapper>,
        >::needs_spawn(&spawner));

        assert!(server.is_finished());
        assert!(server.await.is_ok());
    }
}
