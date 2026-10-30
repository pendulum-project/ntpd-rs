use std::fmt::Display;
use std::sync::{Arc, Mutex};
use std::{net::SocketAddr, ops::Deref};

use ntp_proto::{PollInterval, PollIntervalLimits, ProtocolVersion, SourceConfig};
use rustls23::pki_types::ServerName::IpAddress;
use statime_algo::{LinkConfig, TrackedLinkConfig};
use statime_base::{Link, SourceType, StdController};
use tokio::sync::mpsc;

use crate::daemon::ntp_source::SourceTask;
use crate::daemon::spawn::{CreationParameters, NtpAddress};

#[derive(Debug, PartialEq, Clone)]

pub struct StandardSource {
    pub address: NtpAddress,
    pub ntp_version: ProtocolVersion,
    pub poll_interval_limits: PollIntervalLimits,
    pub desired_error_bound: statime_base::Duration,
    pub delay_decay_rate: f64,
}

use super::{
    ClockId, LinkTerminationReason, SpawnFailureReason, Spawner, SpawnerId,
    resolve_single_ntp_server,
};

pub struct StandardSpawner {
    config: StandardSource,
    state: Arc<Mutex<StandardSpawnerState>>,
}

#[derive(Default)]
struct StandardSpawnerState {
    resolved: Option<SocketAddr>,
    has_spawned: bool,
}

impl StandardSpawner {
    pub fn new(config: StandardSource) -> StandardSpawner {
        StandardSpawner {
            config,
            state: Arc::default(),
        }
    }

    async fn do_resolve(
        state: &Mutex<StandardSpawnerState>,
        force_resolve: bool,
        config: &StandardSource,
    ) -> Option<SocketAddr> {
        // FIXME: Simplify once https://github.com/rust-lang/rust/issues/69663
        // finally gets fixed.
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
            let address = resolve_single_ntp_server(config.address.clone()).await?;
            let mut locked_state = state.lock().unwrap();
            locked_state.resolved = Some(address);
            locked_state.resolved
        }
    }
}

impl<TimeController: StdController> Spawner<TimeController> for StandardSpawner
where
    TimeController::LinkConfig: From<statime_algo::LinkConfig>,
    TimeController::TrackedLinkConfig: From<statime_algo::TrackedLinkConfig>,
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

                        state.lock().unwrap().has_spawned = true;

                        SourceTask::spawn(
                            link_id,
                            config.address.to_string(),
                            addr,
                            clock,
                            source,
                            initial_actions,
                        )
                    },
                ),
            })
        })
    }

    fn needs_spawn(&self) -> bool {
        let state = self.state.lock().unwrap();
        !state.has_spawned
    }

    fn source_terminated(&mut self, id: statime_base::LinkId, reason: LinkTerminationReason) {
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
    use crate::daemon::spawn::standard::StandardSource;
    use crate::daemon::spawn::{Spawner, standard::StandardSpawner};
    use crate::daemon::system::SystemManagers;

    const MESSAGE_BUFFER_SIZE: usize = 2;

    #[tokio::test]
    async fn creates_a_source() {
        let mut spawner = StandardSpawner::new(StandardSource {
            address: NormalizedAddress::with_hardcoded_dns(
                "example.com",
                123,
                vec!["127.0.0.1:123".parse().unwrap()],
            )
            .into(),
            ntp_version: ProtocolVersion::v4_upgrading_to_v5_with_default_tries(),
            poll_interval_limits: ntp_proto::PollIntervalLimits::default(),
            desired_error_bound: statime_base::Duration::from_seconds_nanos(0, 1_000_000),
            delay_decay_rate: 1.0 / 86400f64.sqrt(),
        });

        let managers = SystemManagers::test_managers();

        assert!(<StandardSpawner as Spawner<TestController>>::needs_spawn(
            &spawner
        ));
        let params: CreationParameters<TestController> =
            Box::into_pin(spawner.try_spawn()).await.unwrap();

        assert!(params.tracked_link_config.is_some());

        let link = TestController::create_tracked_link(
            TestController {},
            ClockId::new(),
            None,
            params.link_config,
            params.tracked_link_config.unwrap(),
        )
        .unwrap();

        let handle = (params.creator)(link, NtpClockWrapper::default(), &managers);
        assert!(!<StandardSpawner as Spawner<TestController>>::needs_spawn(
            &spawner
        ));

        handle.abort();
    }

    #[tokio::test]
    async fn recreates_a_source() {
        let mut spawner = StandardSpawner::new(StandardSource {
            address: NormalizedAddress::with_hardcoded_dns(
                "example.com",
                123,
                vec!["127.0.0.1:123".parse().unwrap()],
            )
            .into(),
            ntp_version: ProtocolVersion::v4_upgrading_to_v5_with_default_tries(),
            poll_interval_limits: ntp_proto::PollIntervalLimits::default(),
            desired_error_bound: statime_base::Duration::from_seconds_nanos(0, 1_000_000),
            delay_decay_rate: 1.0 / 86400f64.sqrt(),
        });

        let managers = SystemManagers::test_managers();

        assert!(<StandardSpawner as Spawner<TestController>>::needs_spawn(
            &spawner
        ));
        let params: CreationParameters<TestController> =
            Box::into_pin(spawner.try_spawn()).await.unwrap();

        assert!(params.tracked_link_config.is_some());

        let link = TestController::create_tracked_link(
            TestController {},
            ClockId::new(),
            None,
            params.link_config,
            params.tracked_link_config.unwrap(),
        )
        .unwrap();
        let link_id = link.id();

        let handle = (params.creator)(link, NtpClockWrapper::default(), &managers);
        assert!(!<StandardSpawner as Spawner<TestController>>::needs_spawn(
            &spawner
        ));

        handle.abort();

        <StandardSpawner as Spawner<TestController>>::source_terminated(
            &mut spawner,
            link_id,
            LinkTerminationReason::NetworkIssue,
        );

        assert!(<StandardSpawner as Spawner<TestController>>::needs_spawn(
            &spawner
        ));
        let params: CreationParameters<TestController> =
            Box::into_pin(spawner.try_spawn()).await.unwrap();

        assert!(params.tracked_link_config.is_some());

        let link = TestController::create_tracked_link(
            TestController {},
            ClockId::new(),
            None,
            params.link_config,
            params.tracked_link_config.unwrap(),
        )
        .unwrap();

        let handle = (params.creator)(link, NtpClockWrapper::default(), &managers);
        assert!(!<StandardSpawner as Spawner<TestController>>::needs_spawn(
            &spawner
        ));

        handle.abort();
    }

    #[tokio::test]
    async fn reresolves_on_unreachable() {
        let address_strings = ["127.0.0.1:123", "127.0.0.2:123", "127.0.0.3:123"];
        let addresses = address_strings.map(|addr| addr.parse().unwrap());

        let mut spawner = StandardSpawner::new(StandardSource {
            address: NormalizedAddress::with_hardcoded_dns(
                "europe.pool.ntp.org",
                123,
                addresses.to_vec(),
            )
            .into(),
            ntp_version: ProtocolVersion::v4_upgrading_to_v5_with_default_tries(),
            poll_interval_limits: ntp_proto::PollIntervalLimits::default(),
            desired_error_bound: statime_base::Duration::from_seconds_nanos(0, 1_000_000),
            delay_decay_rate: 1.0 / 86400f64.sqrt(),
        });

        let managers = SystemManagers::test_managers();

        assert!(<StandardSpawner as Spawner<TestController>>::needs_spawn(
            &spawner
        ));
        let params: CreationParameters<TestController> =
            Box::into_pin(spawner.try_spawn()).await.unwrap();

        assert!(params.tracked_link_config.is_some());

        let link = TestController::create_tracked_link(
            TestController {},
            ClockId::new(),
            None,
            params.link_config,
            params.tracked_link_config.unwrap(),
        )
        .unwrap();
        let link_id = link.id();

        let handle = (params.creator)(link, NtpClockWrapper::default(), &managers);
        assert!(!<StandardSpawner as Spawner<TestController>>::needs_spawn(
            &spawner
        ));

        handle.abort();

        <StandardSpawner as Spawner<TestController>>::source_terminated(
            &mut spawner,
            link_id,
            LinkTerminationReason::Unreachable,
        );

        assert!(spawner.state.lock().unwrap().resolved.is_none());
        assert!(<StandardSpawner as Spawner<TestController>>::needs_spawn(
            &spawner
        ));
    }

    #[tokio::test]
    async fn works_if_address_does_not_resolve() {
        let mut spawner = StandardSpawner::new(StandardSource {
            address: NormalizedAddress::with_hardcoded_dns("does.not.resolve", 123, vec![]).into(),
            ntp_version: ProtocolVersion::v4_upgrading_to_v5_with_default_tries(),
            poll_interval_limits: ntp_proto::PollIntervalLimits::default(),
            desired_error_bound: statime_base::Duration::from_seconds_nanos(0, 1_000_000),
            delay_decay_rate: 1.0 / 86400f64.sqrt(),
        });

        assert!(
            Box::into_pin(<StandardSpawner as Spawner<TestController>>::try_spawn(
                &mut spawner
            ))
            .await
            .is_err()
        );
    }
}
