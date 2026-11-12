use std::fmt::Display;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use statime_algo::{LinkConfig, TrackedLinkConfig};
use statime_base::{SourceType, StdController};
use statime_csptp::CsptpSource;
use tokio::sync::mpsc;
use tracing::warn;

use crate::daemon::config::CsptpSourceConfig;
use crate::daemon::csptp_source::{self, CsptpSourceTask};
use crate::daemon::spawn::{
    CreationParameters, LinkTerminationReason, NormalizedAddress, NtpAddress, SpawnFailureReason,
    resolve_single_ntp_server,
};

use super::{ClockId, Spawner, SpawnerId};

#[derive(Debug, PartialEq, Clone)]
pub struct CsptpSpawnerConfig {
    pub address: String,
    pub domain: u8,
    pub poll_interval: std::time::Duration,
    pub response_interval: std::time::Duration,
    pub delay_decay_rate: f64,
}

pub struct CsptpSpawner {
    config: CsptpSpawnerConfig,
    state: Arc<Mutex<CsptpSpawnerState>>,
}

#[derive(Default)]
struct CsptpSpawnerState {
    resolved: Option<IpAddr>,
    has_spawned: bool,
}

impl CsptpSpawner {
    pub fn new(config: CsptpSpawnerConfig) -> CsptpSpawner {
        Self {
            config,
            state: Arc::default(),
        }
    }

    async fn do_resolve(
        state: &Mutex<CsptpSpawnerState>,
        force_resolve: bool,
        config: &CsptpSpawnerConfig,
    ) -> Option<IpAddr> {
        let cached_result = {
            let locked_state = state.lock().unwrap();

            if let (false, Some(addr)) = (force_resolve, locked_state.resolved) {
                Some(addr)
            } else {
                None
            }
        };

        if let Some(addr) = cached_result {
            Some(addr)
        } else {
            let address = resolve_single_ntp_server(NtpAddress(NormalizedAddress::new_from_parts(
                &config.address,
                319,
            )))
            .await?;
            let mut locked_state = state.lock().unwrap();
            locked_state.resolved = Some(address.ip());
            locked_state.resolved
        }
    }
}

impl<TimeController: StdController> Spawner<TimeController> for CsptpSpawner
where
    TimeController::LinkConfig: From<LinkConfig>,
    TimeController::TrackedLinkConfig: From<TrackedLinkConfig>,
    TimeController::Link<Arc<TimeController>>: Send + 'static,
{
    fn try_spawn(&mut self) -> super::TrySpawnFuture<TimeController> {
        let state = self.state.clone();
        let config = self.config.clone();
        Box::new(async move {
            let Some(addr) = Self::do_resolve(&state, false, &config).await else {
                return Err(SpawnFailureReason::RetryableFailure);
            };

            Ok(CreationParameters {
                stype: SourceType::Csptp,
                link_config: LinkConfig {
                    // Not really relevant for csptp as csptp sources have a fixed poll interval.
                    desired_error_bound: statime_base::Duration::from_seconds_nanos(0, 1000),
                    period: None,
                }
                .into(),
                tracked_link_config: Some(
                    TrackedLinkConfig {
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
                        let config = csptp_source::CsptpSourceConfig {
                            address: config.address,
                            domain: config.domain,
                            poll_interval: config.poll_interval,
                            response_interval: config.response_interval,
                        };
                        match addr {
                            IpAddr::V4(addr) => {
                                let network = match managers.netptp_ipv4() {
                                    Ok(network) => network,
                                    Err(e) => {
                                        // Failing here is extremely unusual, being a bit spammy is not
                                        // that problematic as this really should never happen.
                                        warn!("Could not open PTP networking: {e}");
                                        return tokio::spawn(async {
                                            LinkTerminationReason::NetworkIssue
                                        });
                                    }
                                };

                                state.lock().unwrap().has_spawned = true;

                                CsptpSourceTask::spawn(
                                    addr,
                                    config,
                                    controller,
                                    managers.csptp_manager(),
                                    network,
                                )
                            }
                            IpAddr::V6(addr) => {
                                let network = match managers.netptp_ipv6() {
                                    Ok(network) => network,
                                    Err(e) => {
                                        // Failing here is extremely unusual, being a bit spammy is not
                                        // that problematic as this really should never happen.
                                        warn!("Could not open PTP networking: {e}");
                                        return tokio::spawn(async {
                                            LinkTerminationReason::NetworkIssue
                                        });
                                    }
                                };

                                state.lock().unwrap().has_spawned = true;

                                CsptpSourceTask::spawn(
                                    addr,
                                    config,
                                    controller,
                                    managers.csptp_manager(),
                                    network,
                                )
                            }
                        }
                    },
                ),
            })
        })
    }

    fn needs_spawn(&self) -> bool {
        let state = self.state.lock().unwrap();
        !state.has_spawned
    }

    fn source_terminated(
        &mut self,
        id: statime_base::LinkId,
        reason: super::LinkTerminationReason,
    ) {
        let mut state = self.state.lock().unwrap();
        if reason == LinkTerminationReason::Unreachable {
            // force new resolution
            state.resolved = None;
        }
        if reason != LinkTerminationReason::MustDemobilize {
            state.has_spawned = false;
        }
    }
}
