use std::fmt::Display;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::{net::SocketAddr, ops::Deref};

use ntp_proto::{PollIntervalLimits, ProtocolVersion, SourceConfig};
use statime_algo::LinkConfig;
use statime_base::{Link, LinkId, SourceType, StdController};
use tokio::sync::mpsc;
use tracing::warn;

use crate::daemon::ntp_source::SourceTask;
use crate::daemon::spawn::SpawnFailureReason::{self, RetryableFailure};
use crate::daemon::spawn::{CreationParameters, NtpAddress};

use super::{Spawner, SpawnerId};

#[derive(Debug, PartialEq, Clone)]
pub struct NtpPoolSpawnerConfig {
    pub addr: NtpAddress,
    pub count: usize,
    pub ignore: Vec<IpAddr>,
    pub ntp_version: ProtocolVersion,
    pub poll_interval_limits: PollIntervalLimits,
    pub desired_error_bound: statime_base::Duration,
    pub delay_decay_rate: f64,
}

struct NtpPoolSource {
    id: LinkId,
    addr: SocketAddr,
}

pub struct NtpPoolSpawner {
    config: NtpPoolSpawnerConfig,
    state: Arc<Mutex<NtpPoolSpawnerState>>,
}

#[derive(Default)]
struct NtpPoolSpawnerState {
    current_sources: Vec<NtpPoolSource>,
    known_ips: Vec<SocketAddr>,
}

#[derive(Debug)]
pub enum NtpPoolSpawnError {}

impl Display for NtpPoolSpawnError {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unreachable!()
    }
}

impl std::error::Error for NtpPoolSpawnError {}

impl NtpPoolSpawner {
    pub fn new(config: NtpPoolSpawnerConfig) -> NtpPoolSpawner {
        NtpPoolSpawner {
            config,
            state: Arc::default(),
        }
    }
}

impl<TimeController: StdController> Spawner<TimeController> for NtpPoolSpawner
where
    TimeController::LinkConfig: From<statime_algo::LinkConfig>,
    TimeController::TrackedLinkConfig: From<statime_algo::TrackedLinkConfig>,
    TimeController::Link<Arc<TimeController>>: Send + 'static,
{
    fn try_spawn(&mut self) -> super::TrySpawnFuture<TimeController> {
        let config = self.config.clone();
        let state = self.state.clone();

        Box::new(async move {
            if state.lock().unwrap().current_sources.len() >= config.count {
                return Err(SpawnFailureReason::RetryableFailure);
            }

            // FIXME: Simplify once https://github.com/rust-lang/rust/issues/69663
            // finally gets fixed.
            let need_addresses = {
                let state = state.lock().unwrap();
                state.known_ips.is_empty()
            };

            if std::dbg!(need_addresses) {
                match config.addr.lookup_host().await {
                    Ok(addresses) => {
                        let mut state = state.lock().unwrap();
                        // Ensure the borrow checker can check partial mutable borrows.
                        let state = &mut *state;
                        // add the addresses looked up to our list of known ips
                        state.known_ips.append(&mut addresses.collect());
                        // remove known ips that we are already connected to or that we want to ignore
                        state.known_ips.retain(|ip| {
                            !state.current_sources.iter().any(|p| p.addr == *ip)
                                && !config.ignore.iter().any(|ign| *ign == ip.ip())
                        });

                        std::dbg!(&state.known_ips);
                    }
                    Err(e) => {
                        warn!(error = ?e, "error while resolving source address, retrying");
                        return Err(RetryableFailure);
                    }
                }
            }

            let addr = state.lock().unwrap().known_ips.pop();

            if let Some(addr) = addr {
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
                            let (source, initial_actions) = managers.ntp_manager().new_source(
                                addr,
                                SourceConfig {
                                    poll_interval_limits: config.poll_interval_limits,
                                    initial_poll_interval: config.poll_interval_limits.min,
                                },
                                config.ntp_version,
                                controller,
                                None,
                            );

                            state
                                .lock()
                                .unwrap()
                                .current_sources
                                .push(NtpPoolSource { id: link_id, addr });

                            SourceTask::spawn(
                                link_id,
                                config.addr.to_string(),
                                addr,
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
        })
    }

    fn needs_spawn(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.current_sources.len() < self.config.count
    }

    fn source_terminated(&mut self, id: LinkId, reason: super::LinkTerminationReason) {
        let mut state = self.state.lock().unwrap();
        state.current_sources.retain(|p| p.id != id);
    }
}

#[cfg(test)]
mod tests {
    use ntp_proto::ProtocolVersion;

    use ntp_proto::SourceConfig;
    use statime_base::ClockId;
    use statime_base::Controller;
    use statime_base::Link;
    use tokio::sync::mpsc::{self, error::TryRecvError};

    use crate::daemon::clock::NtpClockWrapper;
    use crate::daemon::spawn::CreationParameters;
    use crate::daemon::spawn::LinkTerminationReason;
    use crate::daemon::spawn::NormalizedAddress;
    use crate::daemon::spawn::TestController;
    use crate::daemon::spawn::ntp_pool::NtpPoolSpawnerConfig;
    use crate::daemon::spawn::{Spawner, ntp_pool::NtpPoolSpawner};
    use crate::daemon::system::SystemManagers;

    const MESSAGE_BUFFER_SIZE: usize = 2;

    #[tokio::test]
    async fn creates_multiple_sources() {
        let managers = SystemManagers::test_managers();
        let address_strings = ["127.0.0.1:123", "127.0.0.2:123", "127.0.0.3:123"];
        let addresses = address_strings.map(|addr| addr.parse().unwrap());

        let mut pool = NtpPoolSpawner::new(NtpPoolSpawnerConfig {
            addr: NormalizedAddress::with_hardcoded_dns("example.com", 123, addresses.to_vec())
                .into(),
            count: 2,
            ignore: vec![],
            ntp_version: ProtocolVersion::v4_upgrading_to_v5_with_default_tries(),
            poll_interval_limits: ntp_proto::PollIntervalLimits::default(),
            desired_error_bound: statime_base::Duration::from_seconds_nanos(0, 1_000_000),
            delay_decay_rate: 1.0 / 86400f64.sqrt(),
        });

        assert!(<NtpPoolSpawner as Spawner<TestController>>::needs_spawn(
            &pool
        ));
        let params: CreationParameters<TestController> =
            Box::into_pin(pool.try_spawn()).await.unwrap();

        assert!(params.tracked_link_config.is_some());

        let link = TestController::create_tracked_link(
            TestController {},
            ClockId::new(),
            None,
            params.link_config,
            params.tracked_link_config.unwrap(),
        )
        .unwrap();

        let handle1 = (params.creator)(link, NtpClockWrapper::default(), &managers);

        assert!(<NtpPoolSpawner as Spawner<TestController>>::needs_spawn(
            &pool
        ));
        let params: CreationParameters<TestController> =
            Box::into_pin(pool.try_spawn()).await.unwrap();

        assert!(params.tracked_link_config.is_some());

        let link = TestController::create_tracked_link(
            TestController {},
            ClockId::new(),
            None,
            params.link_config,
            params.tracked_link_config.unwrap(),
        )
        .unwrap();

        let handle2 = (params.creator)(link, NtpClockWrapper::default(), &managers);

        assert!(!<NtpPoolSpawner as Spawner<TestController>>::needs_spawn(
            &pool
        ));

        //FIXME: Check the sources are disjunct once we have sufficient observability for that.

        handle1.abort();
        handle2.abort();
    }

    #[tokio::test]
    async fn respect_ignores() {
        let managers = SystemManagers::test_managers();
        let address_strings = ["127.0.0.1:123", "127.0.0.2:123", "127.0.0.3:123"];
        let addresses = address_strings.map(|addr| addr.parse().unwrap());
        let ignores = vec!["127.0.0.1".parse().unwrap()];

        let mut pool = NtpPoolSpawner::new(NtpPoolSpawnerConfig {
            addr: NormalizedAddress::with_hardcoded_dns("example.com", 123, addresses.to_vec())
                .into(),
            count: 3,
            ignore: ignores.clone(),
            ntp_version: ProtocolVersion::v4_upgrading_to_v5_with_default_tries(),
            poll_interval_limits: ntp_proto::PollIntervalLimits::default(),
            desired_error_bound: statime_base::Duration::from_seconds_nanos(0, 1_000_000),
            delay_decay_rate: 1.0 / 86400f64.sqrt(),
        });

        assert!(<NtpPoolSpawner as Spawner<TestController>>::needs_spawn(
            &pool
        ));
        let params: CreationParameters<TestController> =
            Box::into_pin(pool.try_spawn()).await.unwrap();

        assert!(params.tracked_link_config.is_some());

        let link = TestController::create_tracked_link(
            TestController {},
            ClockId::new(),
            None,
            params.link_config,
            params.tracked_link_config.unwrap(),
        )
        .unwrap();

        let handle1 = (params.creator)(link, NtpClockWrapper::default(), &managers);

        assert!(<NtpPoolSpawner as Spawner<TestController>>::needs_spawn(
            &pool
        ));
        let params: CreationParameters<TestController> =
            Box::into_pin(pool.try_spawn()).await.unwrap();

        assert!(params.tracked_link_config.is_some());

        let link = TestController::create_tracked_link(
            TestController {},
            ClockId::new(),
            None,
            params.link_config,
            params.tracked_link_config.unwrap(),
        )
        .unwrap();

        let handle2 = (params.creator)(link, NtpClockWrapper::default(), &managers);

        assert!(<NtpPoolSpawner as Spawner<TestController>>::needs_spawn(
            &pool
        ));
        assert!(
            Box::into_pin(<NtpPoolSpawner as Spawner<TestController>>::try_spawn(
                &mut pool
            ))
            .await
            .is_err()
        );

        handle1.abort();
        handle2.abort();
    }

    #[tokio::test]
    async fn refills_sources_upto_limit() {
        let managers = SystemManagers::test_managers();
        let address_strings = ["127.0.0.1:123", "127.0.0.2:123", "127.0.0.3:123"];
        let addresses = address_strings.map(|addr| addr.parse().unwrap());

        let mut pool = NtpPoolSpawner::new(NtpPoolSpawnerConfig {
            addr: NormalizedAddress::with_hardcoded_dns("example.com", 123, addresses.to_vec())
                .into(),
            count: 2,
            ignore: vec![],
            ntp_version: ProtocolVersion::v4_upgrading_to_v5_with_default_tries(),
            poll_interval_limits: ntp_proto::PollIntervalLimits::default(),
            desired_error_bound: statime_base::Duration::from_seconds_nanos(0, 1_000_000),
            delay_decay_rate: 1.0 / 86400f64.sqrt(),
        });

        assert!(<NtpPoolSpawner as Spawner<TestController>>::needs_spawn(
            &pool
        ));
        let params: CreationParameters<TestController> =
            Box::into_pin(pool.try_spawn()).await.unwrap();

        assert!(params.tracked_link_config.is_some());

        let link = TestController::create_tracked_link(
            TestController {},
            ClockId::new(),
            None,
            params.link_config,
            params.tracked_link_config.unwrap(),
        )
        .unwrap();
        let id_1 = link.id();

        let handle1 = (params.creator)(link, NtpClockWrapper::default(), &managers);

        assert!(<NtpPoolSpawner as Spawner<TestController>>::needs_spawn(
            &pool
        ));
        let params: CreationParameters<TestController> =
            Box::into_pin(pool.try_spawn()).await.unwrap();

        assert!(params.tracked_link_config.is_some());

        let link = TestController::create_tracked_link(
            TestController {},
            ClockId::new(),
            None,
            params.link_config,
            params.tracked_link_config.unwrap(),
        )
        .unwrap();

        let handle2 = (params.creator)(link, NtpClockWrapper::default(), &managers);

        assert!(!<NtpPoolSpawner as Spawner<TestController>>::needs_spawn(
            &pool
        ));

        handle1.abort();
        <NtpPoolSpawner as Spawner<TestController>>::source_terminated(
            &mut pool,
            id_1,
            LinkTerminationReason::NetworkIssue,
        );

        assert!(<NtpPoolSpawner as Spawner<TestController>>::needs_spawn(
            &pool
        ));
        let params: CreationParameters<TestController> =
            Box::into_pin(pool.try_spawn()).await.unwrap();

        assert!(params.tracked_link_config.is_some());

        let link = TestController::create_tracked_link(
            TestController {},
            ClockId::new(),
            None,
            params.link_config,
            params.tracked_link_config.unwrap(),
        )
        .unwrap();

        let handle3 = (params.creator)(link, NtpClockWrapper::default(), &managers);

        assert!(!<NtpPoolSpawner as Spawner<TestController>>::needs_spawn(
            &pool
        ));

        //FIXME: Check the sources are disjunct once we have sufficient observability for that.

        handle2.abort();
        handle3.abort();
    }

    #[tokio::test]
    async fn works_if_address_does_not_resolve() {
        let mut pool = NtpPoolSpawner::new(NtpPoolSpawnerConfig {
            addr: NormalizedAddress::with_hardcoded_dns("does.not.resolve", 123, vec![]).into(),
            count: 2,
            ignore: vec![],
            ntp_version: ProtocolVersion::v4_upgrading_to_v5_with_default_tries(),
            poll_interval_limits: ntp_proto::PollIntervalLimits::default(),
            desired_error_bound: statime_base::Duration::from_seconds_nanos(0, 1_000_000),
            delay_decay_rate: 1.0 / 86400f64.sqrt(),
        });

        assert!(<NtpPoolSpawner as Spawner<TestController>>::needs_spawn(
            &pool
        ));

        assert!(
            Box::into_pin(<NtpPoolSpawner as Spawner<TestController>>::try_spawn(
                &mut pool
            ))
            .await
            .is_err()
        );
    }
}
