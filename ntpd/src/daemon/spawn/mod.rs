use std::{
    future::Future,
    net::SocketAddr,
    sync::{Arc, atomic::AtomicU64},
};

use ntp_proto::{ClockId, ProtocolVersion, SourceConfig, SourceNtsData};
use statime_base::{LinkId, SourceType, StdController};
use tokio::{
    sync::mpsc,
    task::JoinHandle,
    time::{Instant, timeout},
};
use tracing::warn;

#[cfg(target_os = "linux")]
use crate::daemon::config::CsptpSourceConfig;
#[cfg(feature = "pps")]
use crate::daemon::config::PpsSourceConfig;
use crate::daemon::{
    clock::NtpClockWrapper,
    config::{NtpAddress, SockSourceConfig},
    system::SystemManagers,
};

use super::config::NormalizedAddress;

//#[cfg(target_os = "linux")]
//pub mod csptp;
//pub mod nts;
//pub mod nts_pool;
//pub mod pool;
//#[cfg(feature = "pps")]
//pub mod pps;
//pub mod sock;
pub mod standard;

const NTS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Unique identifier for a spawner.
/// This is used to identify which spawner was used to create a source
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct SpawnerId(u64);

impl SpawnerId {
    pub fn new() -> SpawnerId {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        SpawnerId(COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

impl Default for SpawnerId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkTerminationReason {
    MustDemobilize,
    NetworkIssue,
    Unreachable,
    Failed,
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnFailureReason {
    RetryableFailure,
    NetworkIssue,
}

pub type TrySpawnFuture<TimeController> = Box<
    dyn Future<Output = Result<CreationParameters<TimeController>, SpawnFailureReason>>
        + Sync
        + Send
        + 'static,
>;

pub struct CreationParameters<TimeController: StdController> {
    pub stype: SourceType,
    pub link_config: TimeController::LinkConfig,
    pub tracked_link_config: Option<TimeController::TrackedLinkConfig>,
    pub creator: SourceCreator<TimeController::Link<Arc<TimeController>>>,
}

pub type SourceCreator<LinkController> = Box<
    dyn FnOnce(
            LinkController,
            NtpClockWrapper,
            &SystemManagers,
        ) -> JoinHandle<LinkTerminationReason>
        + Sync
        + Send
        + 'static,
>;

pub trait Spawner<TimeController: StdController> {
    fn try_spawn(&mut self) -> TrySpawnFuture<TimeController>;
    fn needs_spawn(&self) -> bool;
    fn source_terminated(&mut self, id: LinkId, reason: LinkTerminationReason);
}

pub(super) async fn resolve_single_ntp_server(address: NtpAddress) -> Option<SocketAddr> {
    match address.lookup_host().await {
        Ok(addresses) => {
            let mut last_error = None;
            for addr in addresses {
                // Setting up a connection is actually a local only operation for udp sockets.
                // However, it gives the operating system a chance to let us know whether there
                // is a route to the given address.
                if let Err(e) = timestamped_socket::socket::connect_address(
                    addr,
                    timestamped_socket::socket::GeneralTimestampMode::None,
                ) {
                    last_error = Some(e);
                    continue;
                }

                return Some(addr);
            }

            if let Some(e) = last_error {
                warn!("No connection possible to {}: {e}", address.0.server_name);
            } else {
                warn!("Unknown domain name: {}", address.server_name);
            }
            None
        }
        Err(e) => {
            warn!(error = ?e, "error while resolving {}, retrying", address.server_name);
            None
        }
    }
}

#[cfg(test)]
pub use tests::*;

#[cfg(test)]
mod tests {
    use std::future::pending;

    use ntp_proto::SourceConfig;
    use statime_base::{ClockId, Controller, Link, LinkId, StdController};

    use crate::daemon::{clock::NtpClockWrapper, system::SystemManagers};

    #[derive(Default, Debug, Clone, Copy)]
    pub struct ConfigSentinel;
    impl From<statime_algo::LinkConfig> for ConfigSentinel {
        fn from(_value: statime_algo::LinkConfig) -> Self {
            ConfigSentinel
        }
    }

    impl From<statime_algo::TrackedLinkConfig> for ConfigSentinel {
        fn from(_value: statime_algo::TrackedLinkConfig) -> Self {
            ConfigSentinel
        }
    }

    pub struct TestController {}

    impl AsRef<TestController> for TestController {
        fn as_ref(&self) -> &TestController {
            self
        }
    }

    impl Controller for TestController {
        type Clock = NtpClockWrapper;

        type Link<ControllerRef: AsRef<Self>> = TestLink;

        type Error = std::convert::Infallible;

        type ClockConfig = ();

        type LinkConfig = ConfigSentinel;

        type TrackedLinkConfig = ConfigSentinel;

        fn add_clock(
            &self,
            _clock: Self::Clock,
            _config: Self::ClockConfig,
        ) -> Result<statime_base::ClockId, Self::Error> {
            unimplemented!()
        }

        fn remove_clock(&self, _clock_id: statime_base::ClockId) -> Result<(), Self::Error> {
            unimplemented!()
        }

        fn create_tracked_link<ControllerRef: AsRef<Self>>(
            _this: ControllerRef,
            _clock_a: statime_base::ClockId,
            _clock_b: Option<statime_base::ClockId>,
            _config: Self::LinkConfig,
            _tracked_config: Self::TrackedLinkConfig,
        ) -> Result<Self::Link<ControllerRef>, Self::Error> {
            Ok(TestLink(
                LinkId::new(ClockId::new(), ClockId::new()).unwrap(),
            ))
        }

        fn create_untracked_link<ControllerRef: AsRef<Self>>(
            _this: ControllerRef,
            _clock_a: statime_base::ClockId,
            _clock_b: Option<statime_base::ClockId>,
            _config: Self::LinkConfig,
        ) -> Result<Self::Link<ControllerRef>, Self::Error> {
            Ok(TestLink(
                LinkId::new(ClockId::new(), ClockId::new()).unwrap(),
            ))
        }

        fn clock_snapshot(
            &self,
            _clock: statime_base::ClockId,
        ) -> Result<statime_base::TimeSnapshot, Self::Error> {
            unimplemented!()
        }

        fn run<Fut: Future<Output = ()> + Send, F: Send + Fn(core::time::Duration) -> Fut>(
            _this: impl AsRef<Self> + Send,
            _sleep: F,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            pending()
        }
    }

    impl StdController for TestController {
        fn active_links(&self) -> std::vec::Vec<statime_base::ActiveLinkData> {
            unimplemented!()
        }
    }

    pub struct TestLink(LinkId);

    impl Link for TestLink {
        type Error = std::convert::Infallible;

        fn measurement(
            &self,
            measurement: statime_base::Measurement,
            direction: statime_base::Direction,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn external_data_update(
            &self,
            root_delay: statime_base::Duration,
            leap_status: Option<statime_base::LeapStatus>,
            usable: bool,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn active(&self) -> Result<bool, Self::Error> {
            unimplemented!()
        }

        fn importance(&self) -> Result<Option<f64>, Self::Error> {
            unimplemented!()
        }

        fn desired_poll_interval(&self) -> Result<statime_base::Duration, Self::Error> {
            Ok(statime_base::Duration::from_seconds_nanos(16, 0))
        }

        fn id(&self) -> statime_base::LinkId {
            self.0
        }
    }
}
