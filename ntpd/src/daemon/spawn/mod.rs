#[cfg(test)]
use std::sync::Mutex;
use std::{
    fmt,
    future::Future,
    net::SocketAddr,
    ops::Deref,
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
use crate::daemon::{clock::NtpClockWrapper, config::NetworkAddress, system::SystemManagers};

//#[cfg(target_os = "linux")]
//pub mod csptp;
//pub mod nts;
//pub mod nts_pool;
pub mod pool;
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

/// A normalized address has a host and a port part. However, the host may be
/// invalid, we didn't yet perform a DNS lookup.
#[derive(Debug, Clone)]
pub struct NormalizedAddress {
    pub(crate) server_name: String,
    pub(crate) port: u16,

    /// Used to inject socket address into the DNS lookup result
    #[cfg(test)]
    hardcoded_dns_resolve: Option<HardcodedDnsResolve>,
}

impl Eq for NormalizedAddress {}

impl PartialEq for NormalizedAddress {
    fn eq(&self, other: &Self) -> bool {
        self.server_name == other.server_name && self.port == other.port
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Default)]
struct HardcodedDnsResolve {
    addresses: Arc<Mutex<Vec<SocketAddr>>>,
}

#[cfg(test)]
impl From<Vec<SocketAddr>> for HardcodedDnsResolve {
    fn from(value: Vec<SocketAddr>) -> Self {
        Self {
            addresses: Arc::new(Mutex::new(value)),
        }
    }
}

#[cfg(test)]
impl HardcodedDnsResolve {
    fn lookup_host(&self) -> std::vec::IntoIter<SocketAddr> {
        // We don't want to spam a real DNS server during testing. This is an attempt to randomize
        // the returned addresses somewhat.
        let mut addresses = self.addresses.lock().unwrap();

        if let Some(last) = addresses.pop() {
            addresses.insert(0, last);
        }

        let addresses = addresses.to_vec();

        addresses.into_iter()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpAddress(pub NormalizedAddress);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtsKeAddress(pub NormalizedAddress);

impl From<NormalizedAddress> for NtpAddress {
    fn from(addr: NormalizedAddress) -> Self {
        Self(addr)
    }
}

impl From<NetworkAddress> for NtpAddress {
    fn from(value: NetworkAddress) -> Self {
        Self(NormalizedAddress {
            server_name: value.server,
            port: value.port.unwrap_or(123),
            #[cfg(test)]
            hardcoded_dns_resolve: None,
        })
    }
}

impl From<NormalizedAddress> for NtsKeAddress {
    fn from(addr: NormalizedAddress) -> Self {
        Self(addr)
    }
}

impl From<NetworkAddress> for NtsKeAddress {
    fn from(value: NetworkAddress) -> Self {
        Self(NormalizedAddress {
            server_name: value.server,
            port: value.port.unwrap_or(4460),
            #[cfg(test)]
            hardcoded_dns_resolve: None,
        })
    }
}

impl Deref for NtsKeAddress {
    type Target = NormalizedAddress;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for NtpAddress {
    type Target = NormalizedAddress;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl NormalizedAddress {
    const NTP_DEFAULT_PORT: u16 = 123;
    const NTS_KE_DEFAULT_PORT: u16 = 4460;

    /// Specifically, this adds the `:123` port if no port is specified
    pub(crate) fn from_string_ntp(address: String) -> std::io::Result<Self> {
        let (server_name, port) = Self::from_string_help(address, Self::NTP_DEFAULT_PORT)?;

        Ok(Self {
            server_name,
            port,

            #[cfg(test)]
            hardcoded_dns_resolve: None,
        })
    }

    /// Specifically, this adds the `:4460` port if no port is specified
    fn from_string_nts_ke(address: String) -> std::io::Result<Self> {
        let (server_name, port) = Self::from_string_help(address, Self::NTS_KE_DEFAULT_PORT)?;

        Ok(Self {
            server_name,
            port,

            #[cfg(test)]
            hardcoded_dns_resolve: None,
        })
    }

    fn from_string_help(address: String, default_port: u16) -> std::io::Result<(String, u16)> {
        if address.split(':').count() > 2 {
            // IPv6, try to parse it as such
            match address.parse::<SocketAddr>() {
                Ok(socket_addr) => Ok((socket_addr.ip().to_string(), socket_addr.port())),
                Err(e) => {
                    // Could be because of no port, add one and see
                    let address_with_port = format!("[{address}]:{default_port}");
                    if let Ok(socket_addr) = address_with_port.parse::<SocketAddr>() {
                        Ok((socket_addr.ip().to_string(), socket_addr.port()))
                    } else {
                        Err(std::io::Error::other(e))
                    }
                }
            }
        } else if let Some((server_name, port)) = address.split_once(':') {
            // Not ipv6, and we seem to have a port. We cant reasonably
            // check whether the host is valid, but at least check that
            // the port is.
            match port.parse::<u16>() {
                Ok(port) => Ok((server_name.to_string(), port)),
                Err(e) => Err(std::io::Error::other(e)),
            }
        } else {
            // Not ipv6 and no port. As we cant reasonably check host
            // so just append a port
            Ok((address, default_port))
        }
    }

    pub(crate) fn new_from_parts(server_name: &str, port: u16) -> Self {
        Self {
            server_name: server_name.to_string(),
            port,

            #[cfg(test)]
            hardcoded_dns_resolve: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_hardcoded_dns(
        server_name: &str,
        port: u16,
        hardcoded_dns_resolve: Vec<SocketAddr>,
    ) -> Self {
        Self {
            server_name: server_name.to_string(),
            port,
            hardcoded_dns_resolve: Some(HardcodedDnsResolve::from(hardcoded_dns_resolve)),
        }
    }

    pub async fn lookup_host(&self) -> std::io::Result<impl Iterator<Item = SocketAddr> + '_> {
        enum Either<T> {
            Lookup(T),
            #[cfg(test)]
            Hardcoded(std::vec::IntoIter<SocketAddr>),
        }

        impl<T: Iterator<Item = SocketAddr>> Iterator for Either<T> {
            type Item = SocketAddr;

            fn next(&mut self) -> Option<Self::Item> {
                match self {
                    Either::Lookup(lookup) => lookup.next(),
                    #[cfg(test)]
                    Either::Hardcoded(hardcoded) => hardcoded.next(),
                }
            }
        }

        #[cfg(test)]
        if let Some(hardcoded_dns_resolve) = &self.hardcoded_dns_resolve {
            return Ok(Either::Hardcoded(hardcoded_dns_resolve.lookup_host()));
        }

        tokio::net::lookup_host((self.server_name.as_str(), self.port))
            .await
            .map(Either::Lookup)
    }
}

impl std::fmt::Display for NormalizedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.server_name.contains(':') {
            write!(f, "[{}]:{}", self.server_name, self.port)
        } else {
            write!(f, "{}:{}", self.server_name, self.port)
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
