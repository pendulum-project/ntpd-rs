use std::borrow::Cow;
use std::collections::VecDeque;
use std::fmt::Display;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use ntp_proto::tls_utils::Certificate;
use statime_algo::LinkConfig;
use statime_base::{Link, LinkId, SourceType, StdController};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::warn;

use ntp_proto::{
    KeyExchangeClient, NtsClientConfig, NtsError, PollIntervalLimits, ProtocolVersion, SourceConfig,
};

use crate::daemon::dns::{KeResolutionResult, resolve_ke};
use crate::daemon::ntp_source::SourceTask;
use crate::daemon::spawn::SpawnFailureReason::RetryableFailure;
use crate::daemon::spawn::{
    CreationParameters, NormalizedAddress, NtpAddress, NtsKeAddress, SpawnFailureReason,
    resolve_single_ntp_server,
};

use super::{ClockId, Spawner, SpawnerId};

#[derive(Debug, Clone, PartialEq)]
pub struct NtpNtsPoolSpawnerConfig {
    pub address: NtsKeAddress,
    pub certificate_authorities: Arc<[Certificate]>,
    pub enable_srv_resolution: bool,
    pub ntp_version: ProtocolVersion,
    pub poll_interval_limits: PollIntervalLimits,
    pub desired_error_bound: statime_base::Duration,
    pub delay_decay_rate: f64,
    pub count: usize,
}

struct PoolSource {
    id: LinkId,
    remote: String,
}

pub struct NtpNtsPoolSpawner {
    config: NtpNtsPoolSpawnerConfig,
    key_exchange_client: Arc<KeyExchangeClient>,
    state: Arc<Mutex<NtpNtsPoolSpawnerState>>,
}

#[derive(Default)]
struct NtpNtsPoolSpawnerState {
    current_sources: Vec<PoolSource>,
    known_resolutions: VecDeque<KeResolutionResult>,
}

impl NtpNtsPoolSpawnerState {
    fn contains_source(&self, domain: &str) -> bool {
        self.current_sources
            .iter()
            .any(|source| source.remote == domain)
    }
}

impl NtpNtsPoolSpawner {
    pub fn new(config: NtpNtsPoolSpawnerConfig) -> Result<NtpNtsPoolSpawner, NtsError> {
        let key_exchange_client = Arc::new(KeyExchangeClient::new(&NtsClientConfig {
            certificates: config.certificate_authorities.clone(),
            protocol_version: config.ntp_version,
        })?);

        Ok(NtpNtsPoolSpawner {
            config,
            key_exchange_client,
            state: Arc::default(),
        })
    }

    async fn lookup(
        config: &NtpNtsPoolSpawnerConfig,
        state: &Mutex<NtpNtsPoolSpawnerState>,
    ) -> Result<(TcpStream, String, Option<String>), SpawnFailureReason> {
        if config.enable_srv_resolution {
            let mut did_resolution = false;
            loop {
                let need_new_addresses = state.lock().unwrap().known_resolutions.is_empty();

                if need_new_addresses {
                    if did_resolution {
                        warn!(
                            "Could not find more sources for pool at {}",
                            config.address.server_name
                        );
                        return Err(SpawnFailureReason::RetryableFailure);
                    }
                    did_resolution = true;
                    match resolve_ke(&config.address).await {
                        Ok(resolutions) => {
                            let mut state = state.lock().unwrap();
                            state.known_resolutions.extend(resolutions);
                            if state.known_resolutions.is_empty() {
                                warn!("Unresolvable domain name {}", config.address.server_name);
                                return Err(SpawnFailureReason::NetworkIssue);
                            }
                        }
                        Err(e) => {
                            warn!(error=?e, "Error trying to resolve ke server domain name.");
                            return Err(SpawnFailureReason::NetworkIssue);
                        }
                    }
                }

                let mut last_error = None;
                while let Some(addr) = { state.lock().unwrap().known_resolutions.pop_front() } {
                    if let Some(name) = &addr.srv_record_name
                        && state.lock().unwrap().contains_source(name)
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
                    return Ok((
                        io,
                        addr.srv_record_name
                            .clone()
                            .unwrap_or_else(|| config.address.server_name.clone()),
                        addr.srv_record_name,
                    ));
                }

                if let Some(e) = last_error {
                    warn!(error = ?e, "error while attempting key exchange");
                    return Err(SpawnFailureReason::NetworkIssue);
                }
            }
        }
        let io =
            match TcpStream::connect((config.address.server_name.as_str(), config.address.port))
                .await
            {
                Ok(io) => io,
                Err(e) => {
                    warn!(error = ?e, "error while attempting key exchange");
                    return Err(SpawnFailureReason::NetworkIssue);
                }
            };
        Ok((io, config.address.server_name.clone(), None))
    }
}

impl<TimeController: StdController> Spawner<TimeController> for NtpNtsPoolSpawner
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
            let (io, name, remote_name) = Self::lookup(&config, &state).await?;

            match tokio::time::timeout(
                super::NTS_TIMEOUT,
                key_exchange_client.exchange_keys(io, name, []),
            )
            .await
            {
                Ok(Ok(ke))
                    if !state
                        .lock()
                        .unwrap()
                        .contains_source(remote_name.as_ref().unwrap_or(&ke.remote)) =>
                {
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

                                    state.lock().unwrap().current_sources.push(PoolSource {
                                        id: link_id,
                                        remote: remote_name.unwrap_or(ke.remote),
                                    });

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
                Ok(Ok(_)) => {
                    warn!("received an address from pool-ke that we already had, ignoring");
                    Err(SpawnFailureReason::RetryableFailure)
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
        self.state.lock().unwrap().current_sources.len() < self.config.count
    }

    fn source_terminated(
        &mut self,
        id: statime_base::LinkId,
        _reason: super::LinkTerminationReason,
    ) {
        let mut state = self.state.lock().unwrap();
        state.current_sources.retain(|p| p.id != id);
    }
}
