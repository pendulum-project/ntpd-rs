use std::fmt::Display;
use std::sync::{Arc, Mutex};
use std::{net::SocketAddr, ops::Deref};

use ntp_proto::SourceConfig;
use statime_algo::LinkConfig;
use statime_base::{Link, LinkId, SourceType, StdController};
use tokio::sync::mpsc;
use tracing::warn;

use crate::daemon::config::TimestampMode;
use crate::daemon::ntp_source::SourceTask;
use crate::daemon::spawn::CreationParameters;
use crate::daemon::spawn::SpawnFailureReason::{self, RetryableFailure};

use super::super::config::PoolSourceConfig;

use super::{Spawner, SpawnerId};

struct PoolSource {
    id: LinkId,
    addr: SocketAddr,
}

pub struct PoolSpawner {
    config: PoolSourceConfig,
    source_config: SourceConfig,
    state: Arc<Mutex<PoolSpawnerState>>,
}

#[derive(Default)]
struct PoolSpawnerState {
    current_sources: Vec<PoolSource>,
    known_ips: Vec<SocketAddr>,
}

#[derive(Debug)]
pub enum PoolSpawnError {}

impl Display for PoolSpawnError {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unreachable!()
    }
}

impl std::error::Error for PoolSpawnError {}

impl PoolSpawner {
    pub fn new(config: PoolSourceConfig, source_config: SourceConfig) -> PoolSpawner {
        PoolSpawner {
            config,
            source_config,
            state: Arc::default(),
        }
    }
}

impl<TimeController: StdController> Spawner<TimeController> for PoolSpawner
where
    TimeController::LinkConfig: From<statime_algo::LinkConfig>,
    TimeController::TrackedLinkConfig: From<statime_algo::TrackedLinkConfig>,
    TimeController::Link<Arc<TimeController>>: Send + 'static,
{
    fn try_spawn(&mut self) -> super::TrySpawnFuture<TimeController> {
        let config = self.config.clone();
        let source_config = self.source_config;
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
                        desired_error_bound: statime_base::Duration::from_seconds_nanos(
                            0, 1_000_000,
                        ),
                        period: None,
                    }
                    .into(),
                    tracked_link_config: Some(
                        statime_algo::TrackedLinkConfig {
                            decay_rate: 1. / 86400f64.sqrt(),
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
                                source_config,
                                config.ntp_version,
                                controller,
                                None,
                            );

                            state
                                .lock()
                                .unwrap()
                                .current_sources
                                .push(PoolSource { id: link_id, addr });

                            SourceTask::spawn(
                                link_id,
                                config.addr.to_string(),
                                addr,
                                None,
                                clock,
                                TimestampMode::Software,
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
    use crate::daemon::spawn::TestController;
    use crate::daemon::system::SystemManagers;
    use crate::daemon::{
        config::{NormalizedAddress, PoolSourceConfig},
        spawn::{Spawner, pool::PoolSpawner},
    };

    const MESSAGE_BUFFER_SIZE: usize = 2;

    #[tokio::test]
    async fn creates_multiple_sources() {
        let managers = SystemManagers::test_managers();
        let address_strings = ["127.0.0.1:123", "127.0.0.2:123", "127.0.0.3:123"];
        let addresses = address_strings.map(|addr| addr.parse().unwrap());

        let mut pool = PoolSpawner::new(
            PoolSourceConfig {
                addr: NormalizedAddress::with_hardcoded_dns("example.com", 123, addresses.to_vec())
                    .into(),
                count: 2,
                ignore: vec![],
                ntp_version: ProtocolVersion::v4_upgrading_to_v5_with_default_tries(),
            },
            SourceConfig::default(),
        );

        assert!(<PoolSpawner as Spawner<TestController>>::needs_spawn(&pool));
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

        assert!(<PoolSpawner as Spawner<TestController>>::needs_spawn(&pool));
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

        assert!(!<PoolSpawner as Spawner<TestController>>::needs_spawn(
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

        let mut pool = PoolSpawner::new(
            PoolSourceConfig {
                addr: NormalizedAddress::with_hardcoded_dns("example.com", 123, addresses.to_vec())
                    .into(),
                count: 3,
                ignore: ignores.clone(),
                ntp_version: ProtocolVersion::v4_upgrading_to_v5_with_default_tries(),
            },
            SourceConfig::default(),
        );

        assert!(<PoolSpawner as Spawner<TestController>>::needs_spawn(&pool));
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

        assert!(<PoolSpawner as Spawner<TestController>>::needs_spawn(&pool));
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

        assert!(<PoolSpawner as Spawner<TestController>>::needs_spawn(&pool));
        assert!(
            Box::into_pin(<PoolSpawner as Spawner<TestController>>::try_spawn(
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

        let mut pool = PoolSpawner::new(
            PoolSourceConfig {
                addr: NormalizedAddress::with_hardcoded_dns("example.com", 123, addresses.to_vec())
                    .into(),
                count: 2,
                ignore: vec![],
                ntp_version: ProtocolVersion::v4_upgrading_to_v5_with_default_tries(),
            },
            SourceConfig::default(),
        );

        assert!(<PoolSpawner as Spawner<TestController>>::needs_spawn(&pool));
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

        assert!(<PoolSpawner as Spawner<TestController>>::needs_spawn(&pool));
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

        assert!(!<PoolSpawner as Spawner<TestController>>::needs_spawn(
            &pool
        ));

        handle1.abort();
        <PoolSpawner as Spawner<TestController>>::source_terminated(
            &mut pool,
            id_1,
            LinkTerminationReason::NetworkIssue,
        );

        assert!(<PoolSpawner as Spawner<TestController>>::needs_spawn(&pool));
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

        assert!(!<PoolSpawner as Spawner<TestController>>::needs_spawn(
            &pool
        ));

        //FIXME: Check the sources are disjunct once we have sufficient observability for that.

        handle2.abort();
        handle3.abort();
    }

    #[tokio::test]
    async fn works_if_address_does_not_resolve() {
        let mut pool = PoolSpawner::new(
            PoolSourceConfig {
                addr: NormalizedAddress::with_hardcoded_dns("does.not.resolve", 123, vec![]).into(),
                count: 2,
                ignore: vec![],
                ntp_version: ProtocolVersion::v4_upgrading_to_v5_with_default_tries(),
            },
            SourceConfig::default(),
        );

        assert!(<PoolSpawner as Spawner<TestController>>::needs_spawn(&pool));

        assert!(
            Box::into_pin(<PoolSpawner as Spawner<TestController>>::try_spawn(
                &mut pool
            ))
            .await
            .is_err()
        );
    }
}
