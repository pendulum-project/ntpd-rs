use std::{
    collections::hash_map::RandomState,
    hash::BuildHasher,
    io::Cursor,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use ntp_proto::{
    DecodedServerCookie, KeySet, NoCipher, NtpAssociationMode, NtpClock, NtpPacket, NtpTimestamp,
    SystemSnapshot,
};
use ntp_udp::{InterfaceName, UdpSocket};
use prometheus_client::metrics::counter::Counter;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::config::{FilterAction, ServerConfig};

// Maximum size of udp packet we handle
const MAX_PACKET_SIZE: usize = 1024;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ServerStats {
    pub received_packets: WrappedCounter,
    pub accepted_packets: WrappedCounter,
    pub denied_packets: WrappedCounter,
    pub ignored_packets: WrappedCounter,
    pub rate_limited_packets: WrappedCounter,
    pub response_send_errors: WrappedCounter,
}

#[derive(Default, Debug, Clone)]
pub struct WrappedCounter(Counter);

impl Serialize for WrappedCounter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.0.get())
    }
}

impl<'de> Deserialize<'de> for WrappedCounter {
    fn deserialize<D>(deserializer: D) -> Result<WrappedCounter, D::Error>
    where
        D: Deserializer<'de>,
    {
        let d: u64 = Deserialize::deserialize(deserializer)?;
        let counter: Counter = Default::default();
        counter
            .inner()
            .store(d, std::sync::atomic::Ordering::Relaxed);
        Ok(WrappedCounter(counter))
    }
}

impl std::ops::Deref for WrappedCounter {
    type Target = Counter;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct ServerTask<C: 'static + NtpClock + Send> {
    config: ServerConfig,
    network_wait_period: std::time::Duration,
    system_receiver: tokio::sync::watch::Receiver<SystemSnapshot>,
    keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
    system: SystemSnapshot,
    client_cache: TimestampedCache<IpAddr>,
    clock: C,
    interface: Option<InterfaceName>,
    stats: ServerStats,
}

#[derive(Debug)]
enum AcceptResult<'a> {
    Accept {
        packet: NtpPacket<'a>,
        max_response_size: usize,
        decoded_cookie: Option<DecodedServerCookie>,
        peer_addr: SocketAddr,
        recv_timestamp: NtpTimestamp,
    },
    Ignore,
    Deny {
        packet: NtpPacket<'a>,
        max_response_size: usize,
        decoded_cookie: Option<DecodedServerCookie>,
        peer_addr: SocketAddr,
    },
    RateLimit {
        packet: NtpPacket<'a>,
        max_response_size: usize,
        decoded_cookie: Option<DecodedServerCookie>,
        peer_addr: SocketAddr,
    },
    NetworkGone,
}

impl<C: 'static + NtpClock + Send> ServerTask<C> {
    pub fn spawn(
        config: ServerConfig,
        stats: ServerStats,
        mut system_receiver: tokio::sync::watch::Receiver<SystemSnapshot>,
        keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
        clock: C,
        interface: Option<InterfaceName>,
        network_wait_period: Duration,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let rate_limiting_cutoff = config.rate_limiting_cutoff;
            let rate_limiting_cache_size = config.rate_limiting_cache_size;
            let system = *system_receiver.borrow_and_update();

            let mut process = ServerTask {
                config,
                network_wait_period,
                system,
                system_receiver,
                keyset,
                clock,
                interface,
                client_cache: TimestampedCache::new(rate_limiting_cache_size),
                stats,
            };

            process.serve(rate_limiting_cutoff).await
        })
    }

    fn filter(&self, addr: &IpAddr) -> Option<FilterAction> {
        if self.config.denylist.is_in(addr) {
            // First apply denylist
            Some(self.config.denylist_action)
        } else if !self.config.allowlist.is_in(addr) {
            // Then allowlist
            Some(self.config.allowlist_action)
        } else {
            None
        }
    }

    #[instrument(level = "debug", skip(self), fields(
        addr = debug(self.config.addr),
    ))]
    async fn serve(&mut self, rate_limiting_cutoff: Duration) {
        let mut cur_socket = None;
        loop {
            let socket = if let Some(ref socket) = cur_socket {
                socket
            } else {
                cur_socket = Some(loop {
                    match UdpSocket::server(self.config.addr, self.interface).await {
                        Ok(socket) => break socket,
                        Err(error) => {
                            warn!(?error, "Could not open server socket");
                            tokio::time::sleep(self.network_wait_period).await;
                        }
                    }
                });
                // system may now be wildly out of date, ensure it is always updated.
                self.system = *self.system_receiver.borrow_and_update();

                cur_socket.as_ref().unwrap()
            };

            let mut buf = [0_u8; MAX_PACKET_SIZE];
            tokio::select! {
                recv_res = socket.recv(&mut buf) => {
                    if !self.serve_packet(socket, &buf, recv_res, rate_limiting_cutoff).await {
                        cur_socket = None;
                    }
                },
                _ = self.system_receiver.changed(), if self.system_receiver.has_changed().is_ok() => {
                    self.system = *self.system_receiver.borrow_and_update();
                }
            }
        }
    }

    async fn serve_packet(
        &mut self,
        socket: &UdpSocket,
        buf: &[u8],
        recv_res: std::io::Result<(usize, SocketAddr, Option<NtpTimestamp>)>,
        rate_limiting_cutoff: Duration,
    ) -> bool {
        self.stats.received_packets.inc();
        let accept_result = self.accept_packet(rate_limiting_cutoff, recv_res, buf);

        match accept_result {
            AcceptResult::Accept {
                packet,
                max_response_size,
                decoded_cookie,
                peer_addr,
                recv_timestamp,
            } => {
                self.stats.accepted_packets.inc();

                let keyset = self.keyset.borrow().clone();
                let mut buf = [0; MAX_PACKET_SIZE];
                let mut cursor = Cursor::new(buf.as_mut_slice());
                let serialize_result = match decoded_cookie {
                    Some(decoded_cookie) => {
                        let response = NtpPacket::nts_timestamp_response(
                            &self.system,
                            packet,
                            recv_timestamp,
                            &self.clock,
                            &decoded_cookie,
                            &keyset,
                        );
                        response.serialize(&mut cursor, decoded_cookie.s2c.as_ref())
                    }
                    None => {
                        let response = NtpPacket::timestamp_response(
                            &self.system,
                            packet,
                            recv_timestamp,
                            &self.clock,
                        );
                        response.serialize(&mut cursor, &NoCipher)
                    }
                };

                if let Err(serialize_err) = serialize_result {
                    error!(error=?serialize_err, "Could not serialize response");
                    return true;
                }

                if cursor.position() as usize > max_response_size {
                    error!("Generated response that was larger than the request");
                    return true;
                }

                if let Err(send_err) = socket
                    .send_to(&cursor.get_ref()[0..cursor.position() as usize], peer_addr)
                    .await
                {
                    self.stats.response_send_errors.inc();
                    debug!(error=?send_err, "Could not send response packet");
                }
            }
            AcceptResult::Deny {
                packet,
                max_response_size,
                decoded_cookie,
                peer_addr,
            } => {
                self.stats.denied_packets.inc();

                let mut buf = [0; 48];
                let mut cursor = Cursor::new(buf.as_mut_slice());
                let serialize_result = match decoded_cookie {
                    Some(decoded_cookie) => {
                        let response = NtpPacket::nts_deny_response(packet);
                        response.serialize(&mut cursor, decoded_cookie.s2c.as_ref())
                    }
                    None => {
                        let response = NtpPacket::deny_response(packet);
                        response.serialize(&mut cursor, &NoCipher)
                    }
                };

                if let Err(serialize_err) = serialize_result {
                    self.stats.response_send_errors.inc();
                    error!(error=?serialize_err, "Could not serialize response");
                    return true;
                }

                if cursor.position() as usize > max_response_size {
                    error!("Generated response that was larger than the request");
                    return true;
                }

                if let Err(send_err) = socket
                    .send_to(&cursor.get_ref()[0..cursor.position() as usize], peer_addr)
                    .await
                {
                    self.stats.response_send_errors.inc();
                    warn!(error=?send_err, "Could not send deny packet");
                }
            }
            AcceptResult::NetworkGone => {
                error!("Server connection gone");
                return false;
            }
            AcceptResult::RateLimit {
                packet,
                max_response_size,
                decoded_cookie,
                peer_addr,
            } => {
                self.stats.rate_limited_packets.inc();

                let mut buf = [0; 48];
                let mut cursor = Cursor::new(buf.as_mut_slice());
                let serialize_result = match decoded_cookie {
                    Some(decoded_cookie) => {
                        let response = NtpPacket::nts_rate_limit_response(packet);
                        response.serialize(&mut cursor, decoded_cookie.s2c.as_ref())
                    }
                    None => {
                        let response = NtpPacket::rate_limit_response(packet);
                        response.serialize(&mut cursor, &NoCipher)
                    }
                };

                if let Err(serialize_err) = serialize_result {
                    self.stats.response_send_errors.inc();
                    error!(error=?serialize_err, "Could not serialize response");
                    return true;
                }

                if cursor.position() as usize > max_response_size {
                    error!("Generated response that was larger than the request");
                    return true;
                }

                if let Err(send_err) = socket
                    .send_to(&cursor.get_ref()[0..cursor.position() as usize], peer_addr)
                    .await
                {
                    self.stats.response_send_errors.inc();
                    debug!(error=?send_err, "Could not send response packet");
                }
            }
            AcceptResult::Ignore => {
                self.stats.ignored_packets.inc();
            }
        }
        true
    }

    fn accept_packet<'a>(
        &mut self,
        rate_limiting_cutoff: Duration,
        result: Result<(usize, SocketAddr, Option<NtpTimestamp>), std::io::Error>,
        buf: &'a [u8],
    ) -> AcceptResult<'a> {
        match result {
            Ok((size, peer_addr, Some(recv_timestamp))) if size >= 48 => {
                // Note: packets are allowed to be bigger when including extensions.
                // we don't expect many, but the client may still send them. We try
                // to see if the message still makes sense with some bytes dropped.
                // Messages of fewer than 48 bytes are skipped entirely
                match self.filter(&peer_addr.ip()) {
                    Some(FilterAction::Deny) => {
                        match self.accept_data(&buf[..size], peer_addr, recv_timestamp) {
                            // We should send deny messages only to reasonable requests
                            // otherwise two servers could end up in a loop of sending
                            // deny's to each other.
                            AcceptResult::Accept {
                                packet,
                                max_response_size,
                                decoded_cookie,
                                peer_addr,
                                ..
                            } => AcceptResult::Deny {
                                packet,
                                max_response_size,
                                decoded_cookie,
                                peer_addr,
                            },
                            v => v,
                        }
                    }
                    Some(FilterAction::Ignore) => AcceptResult::Ignore,
                    None => {
                        let timestamp = Instant::now();
                        let cutoff = rate_limiting_cutoff;
                        let too_soon =
                            !self
                                .client_cache
                                .is_allowed(peer_addr.ip(), timestamp, cutoff);

                        match self.accept_data(&buf[..size], peer_addr, recv_timestamp) {
                            AcceptResult::Accept {
                                packet,
                                max_response_size,
                                decoded_cookie,
                                peer_addr,
                                ..
                            } if too_soon => AcceptResult::RateLimit {
                                packet,
                                max_response_size,
                                decoded_cookie,
                                peer_addr,
                            },
                            accept_result => accept_result,
                        }
                    }
                }
            }
            Ok((size, _, Some(_))) => {
                info!(expected = 48, actual = size, "received packet is too small");

                AcceptResult::Ignore
            }
            Ok((size, _, None)) => {
                warn!(?size, "received a packet without a timestamp");

                AcceptResult::Ignore
            }
            Err(receive_error) => {
                warn!(?receive_error, "could not receive packet");

                match receive_error.raw_os_error() {
                    // For a server, we only trigger NetworkGone restarts
                    // on ENETDOWN. ENETUNREACH, EHOSTDOWN and EHOSTUNREACH
                    // do not signal restart-worthy conditions for the a
                    // server (they essentially indicate problems with the
                    // remote network/host, which is not relevant for a server).
                    // Furthermore, they can conceivably be triggered by a
                    // malicious third party, and triggering restart on them
                    // would then result in a denial-of-service.
                    Some(libc::ENETDOWN) => AcceptResult::NetworkGone,
                    _ => AcceptResult::Ignore,
                }
            }
        }
    }

    fn accept_data<'a>(
        &self,
        buf: &'a [u8],
        peer_addr: SocketAddr,
        recv_timestamp: NtpTimestamp,
    ) -> AcceptResult<'a> {
        let keyset = self.keyset.borrow().clone();
        match NtpPacket::deserialize(buf, keyset.as_ref()) {
            Ok((packet, decoded_cookie)) => match packet.mode() {
                NtpAssociationMode::Client => {
                    trace!("NTP client request accepted from {}", peer_addr);
                    AcceptResult::Accept {
                        packet,
                        max_response_size: buf.len(),
                        decoded_cookie,
                        peer_addr,
                        recv_timestamp,
                    }
                }
                _ => {
                    trace!(
                        "NTP packet with unkown mode {:?} ignored from {}",
                        packet.mode(),
                        peer_addr
                    );
                    AcceptResult::Ignore
                }
            },
            Err(e) => {
                info!("received invalid packet: {}", e);
                AcceptResult::Ignore
            }
        }
    }
}

/// A size-bounded cache where each entry is timestamped.
///
/// The planned use is in rate limiting: we keep track of when a peer last checked in. If it checks
/// in too often, we issue a rate limiting KISS code.
///
/// For this use case we want fast
///
/// - lookups: for each incomming IP we must check when it last checked in
/// - inserts: for each incomming IP we store that its most recent checkin is now
///
/// Hence, this data structure is a vector, and we use a simple hash function to turn the incomming
/// address into an index. Lookups and inserts are therefore O(1).
///
/// The likelyhood of hash collisions can be controlled by changing the size of the cache. Hash collisions
/// will happen, so this cache should not be relied on if perfect alerting is deemed critical.
#[derive(Debug)]
struct TimestampedCache<T> {
    randomstate: RandomState,
    elements: Vec<Option<(T, Instant)>>,
}

impl<T: std::hash::Hash + Eq> TimestampedCache<T> {
    fn new(length: usize) -> Self {
        Self {
            // looks a bit odd, but prevents a `Clone` constraint
            elements: std::iter::repeat_with(|| None).take(length).collect(),
            randomstate: RandomState::new(),
        }
    }

    fn index(&self, item: &T) -> usize {
        use std::hash::Hasher;

        let mut hasher = self.randomstate.build_hasher();

        item.hash(&mut hasher);

        hasher.finish() as usize % self.elements.len()
    }

    fn is_allowed(&mut self, item: T, timestamp: Instant, cutoff: Duration) -> bool {
        if self.elements.is_empty() {
            // cache disabled, always OK
            return true;
        }

        let index = self.index(&item);

        // check if the current occupant of this slot is actually the same item
        let timestamp_if_same = self.elements[index]
            .as_ref()
            .and_then(|(v, t)| (&item == v).then_some(t))
            .copied();

        self.elements[index] = Some((item, timestamp));

        if let Some(old_timestamp) = timestamp_if_same {
            // old and new are the same; check the time
            timestamp.duration_since(old_timestamp) >= cutoff
        } else {
            // old and new are different; this is always OK
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ntp_proto::{
        KeySetProvider, NtpDuration, NtpLeapIndicator, PollInterval, PollIntervalLimits,
        ReferenceId,
    };

    use crate::ipfilter::IpFilter;

    use super::*;

    const EPOCH_OFFSET: u32 = (70 * 365 + 17) * 86400;

    #[derive(Debug, Clone, Default)]
    struct TestClock {}

    impl NtpClock for TestClock {
        type Error = std::time::SystemTimeError;

        fn now(&self) -> std::result::Result<NtpTimestamp, Self::Error> {
            let cur =
                std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH)?;

            Ok(NtpTimestamp::from_seconds_nanos_since_ntp_era(
                EPOCH_OFFSET.wrapping_add(cur.as_secs() as u32),
                cur.subsec_nanos(),
            ))
        }

        fn set_frequency(&self, _freq: f64) -> Result<NtpTimestamp, Self::Error> {
            panic!("Shouldn't be called by peer");
        }

        fn step_clock(&self, _offset: NtpDuration) -> Result<NtpTimestamp, Self::Error> {
            panic!("Shouldn't be called by peer");
        }

        fn enable_ntp_algorithm(&self) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by peer");
        }

        fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by peer");
        }

        fn ntp_algorithm_update(
            &self,
            _offset: NtpDuration,
            _poll_interval: PollInterval,
        ) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by peer");
        }

        fn error_estimate_update(
            &self,
            _est_error: NtpDuration,
            _max_error: NtpDuration,
        ) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by peer");
        }

        fn status_update(&self, _leap_status: NtpLeapIndicator) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by peer");
        }
    }

    fn serialize_packet_unencryped(send_packet: &NtpPacket) -> [u8; 48] {
        let mut buf = [0; 48];
        let mut cursor = Cursor::new(buf.as_mut_slice());
        send_packet.serialize(&mut cursor, &NoCipher).unwrap();

        assert_eq!(cursor.position(), 48);

        buf
    }

    #[tokio::test]
    async fn test_server_filter_allow_ok() {
        let config = ServerConfig {
            addr: "127.0.0.1:9000".parse().unwrap(),
            denylist: IpFilter::none(),
            denylist_action: FilterAction::Ignore,
            allowlist: IpFilter::new(&["127.0.0.0/24".parse().unwrap()]),
            allowlist_action: FilterAction::Ignore,
            rate_limiting_cutoff: Duration::from_secs(1),
            rate_limiting_cache_size: 32,
        };
        let (_, system_snapshots) = tokio::sync::watch::channel(SystemSnapshot::default());
        let clock = TestClock {};
        let (_, keyset) = tokio::sync::watch::channel(KeySetProvider::new(1).get());

        let server = ServerTask::spawn(
            config,
            Default::default(),
            system_snapshots,
            keyset,
            clock,
            InterfaceName::DEFAULT,
            Duration::from_secs(1),
        );

        let mut socket = UdpSocket::client(
            "127.0.0.1:9001".parse().unwrap(),
            "127.0.0.1:9000".parse().unwrap(),
        )
        .await
        .unwrap();
        let (packet, id) = NtpPacket::poll_message(PollIntervalLimits::default().min);

        let serialized = serialize_packet_unencryped(&packet);
        socket.send(&serialized).await.unwrap();

        let mut buf = [0; 48];
        tokio::time::timeout(Duration::from_millis(10), socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = NtpPacket::deserialize(&buf, &NoCipher).unwrap().0;
        assert_ne!(packet.stratum(), 0);
        assert!(packet.valid_server_response(id, false));

        server.abort();
    }

    #[tokio::test]
    async fn test_server_filter_allow_deny() {
        let config = ServerConfig {
            addr: "127.0.0.1:9002".parse().unwrap(),
            denylist: IpFilter::none(),
            denylist_action: FilterAction::Ignore,
            allowlist: IpFilter::new(&["128.0.0.0/24".parse().unwrap()]),
            allowlist_action: FilterAction::Deny,
            rate_limiting_cutoff: Duration::from_secs(1),
            rate_limiting_cache_size: 32,
        };
        let (_, system_snapshots) = tokio::sync::watch::channel(SystemSnapshot::default());
        let clock = TestClock {};
        let (_, keyset) = tokio::sync::watch::channel(KeySetProvider::new(1).get());

        let server = ServerTask::spawn(
            config,
            Default::default(),
            system_snapshots,
            keyset,
            clock,
            InterfaceName::DEFAULT,
            Duration::from_secs(1),
        );

        let mut socket = UdpSocket::client(
            "127.0.0.1:9003".parse().unwrap(),
            "127.0.0.1:9002".parse().unwrap(),
        )
        .await
        .unwrap();
        let (packet, id) = NtpPacket::poll_message(PollIntervalLimits::default().min);

        let serialized = serialize_packet_unencryped(&packet);
        socket.send(&serialized).await.unwrap();

        let mut buf = [0; 48];
        tokio::time::timeout(Duration::from_millis(10), socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = NtpPacket::deserialize(&buf, &NoCipher).unwrap().0;
        assert_eq!(packet.stratum(), 0);
        assert_eq!(packet.reference_id(), ReferenceId::KISS_DENY);
        assert!(packet.valid_server_response(id, false));

        server.abort();
    }

    #[tokio::test]
    async fn test_server_filter_allow_ignore() {
        let config = ServerConfig {
            addr: "127.0.0.1:9004".parse().unwrap(),
            denylist: IpFilter::none(),
            denylist_action: FilterAction::Ignore,
            allowlist: IpFilter::new(&["128.0.0.0/24".parse().unwrap()]),
            allowlist_action: FilterAction::Ignore,
            rate_limiting_cutoff: Duration::from_secs(1),
            rate_limiting_cache_size: 32,
        };
        let (_, system_snapshots) = tokio::sync::watch::channel(SystemSnapshot::default());
        let clock = TestClock {};
        let (_, keyset) = tokio::sync::watch::channel(KeySetProvider::new(1).get());

        let server = ServerTask::spawn(
            config,
            Default::default(),
            system_snapshots,
            keyset,
            clock,
            InterfaceName::DEFAULT,
            Duration::from_secs(1),
        );

        let mut socket = UdpSocket::client(
            "127.0.0.1:9005".parse().unwrap(),
            "127.0.0.1:9004".parse().unwrap(),
        )
        .await
        .unwrap();
        let (packet, _) = NtpPacket::poll_message(PollIntervalLimits::default().min);

        let serialized = serialize_packet_unencryped(&packet);
        socket.send(&serialized).await.unwrap();

        let mut buf = [0; 48];
        let res = tokio::time::timeout(Duration::from_millis(10), socket.recv(&mut buf)).await;
        assert!(res.is_err());

        server.abort();
    }

    #[tokio::test]
    async fn test_server_filter_deny_ok() {
        let config = ServerConfig {
            addr: "127.0.0.1:9006".parse().unwrap(),
            denylist: IpFilter::new(&["192.168.0.0/16".parse().unwrap()]),
            denylist_action: FilterAction::Ignore,
            allowlist: IpFilter::all(),
            allowlist_action: FilterAction::Ignore,
            rate_limiting_cutoff: Duration::from_secs(1),
            rate_limiting_cache_size: 32,
        };
        let (_, system_snapshots) = tokio::sync::watch::channel(SystemSnapshot::default());
        let clock = TestClock {};
        let (_, keyset) = tokio::sync::watch::channel(KeySetProvider::new(1).get());

        let server = ServerTask::spawn(
            config,
            Default::default(),
            system_snapshots,
            keyset,
            clock,
            InterfaceName::DEFAULT,
            Duration::from_secs(1),
        );

        let mut socket = UdpSocket::client(
            "127.0.0.1:9007".parse().unwrap(),
            "127.0.0.1:9006".parse().unwrap(),
        )
        .await
        .unwrap();
        let (packet, id) = NtpPacket::poll_message(PollIntervalLimits::default().min);

        let serialized = serialize_packet_unencryped(&packet);
        socket.send(&serialized).await.unwrap();

        let mut buf = [0; 48];
        tokio::time::timeout(Duration::from_millis(10), socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = NtpPacket::deserialize(&buf, &NoCipher).unwrap().0;
        assert_ne!(packet.stratum(), 0);
        assert!(packet.valid_server_response(id, false));

        server.abort();
    }

    #[tokio::test]
    async fn test_server_filter_deny_deny() {
        let config = ServerConfig {
            addr: "127.0.0.1:9008".parse().unwrap(),
            denylist: IpFilter::new(&["127.0.0.0/24".parse().unwrap()]),
            denylist_action: FilterAction::Deny,
            allowlist: IpFilter::all(),
            allowlist_action: FilterAction::Ignore,
            rate_limiting_cutoff: Duration::from_secs(1),
            rate_limiting_cache_size: 32,
        };
        let (_, system_snapshots) = tokio::sync::watch::channel(SystemSnapshot::default());
        let clock = TestClock {};
        let (_, keyset) = tokio::sync::watch::channel(KeySetProvider::new(1).get());

        let server = ServerTask::spawn(
            config,
            Default::default(),
            system_snapshots,
            keyset,
            clock,
            InterfaceName::DEFAULT,
            Duration::from_secs(1),
        );

        let mut socket = UdpSocket::client(
            "127.0.0.1:9009".parse().unwrap(),
            "127.0.0.1:9008".parse().unwrap(),
        )
        .await
        .unwrap();
        let (packet, id) = NtpPacket::poll_message(PollIntervalLimits::default().min);

        let serialized = serialize_packet_unencryped(&packet);
        socket.send(&serialized).await.unwrap();

        let mut buf = [0; 48];
        tokio::time::timeout(Duration::from_millis(10), socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = NtpPacket::deserialize(&buf, &NoCipher).unwrap().0;
        assert_eq!(packet.stratum(), 0);
        assert_eq!(packet.reference_id(), ReferenceId::KISS_DENY);
        assert!(packet.valid_server_response(id, false));

        server.abort();
    }

    #[tokio::test]
    async fn test_server_filter_deny_ignore() {
        let config = ServerConfig {
            addr: "127.0.0.1:9010".parse().unwrap(),
            denylist: IpFilter::new(&["127.0.0.0/24".parse().unwrap()]),
            denylist_action: FilterAction::Ignore,
            allowlist: IpFilter::all(),
            allowlist_action: FilterAction::Ignore,
            rate_limiting_cutoff: Duration::from_secs(1),
            rate_limiting_cache_size: 32,
        };
        let (_, system_snapshots) = tokio::sync::watch::channel(SystemSnapshot::default());
        let clock = TestClock {};
        let (_, keyset) = tokio::sync::watch::channel(KeySetProvider::new(1).get());

        let server = ServerTask::spawn(
            config,
            Default::default(),
            system_snapshots,
            keyset,
            clock,
            InterfaceName::DEFAULT,
            Duration::from_secs(1),
        );

        let mut socket = UdpSocket::client(
            "127.0.0.1:9011".parse().unwrap(),
            "127.0.0.1:9010".parse().unwrap(),
        )
        .await
        .unwrap();
        let (packet, _) = NtpPacket::poll_message(PollIntervalLimits::default().min);

        let serialized = serialize_packet_unencryped(&packet);
        socket.send(&serialized).await.unwrap();

        let mut buf = [0; 48];
        let res = tokio::time::timeout(Duration::from_millis(10), socket.recv(&mut buf)).await;
        assert!(res.is_err());

        server.abort();
    }

    #[tokio::test]
    async fn test_server_rate_limit() {
        let config = ServerConfig {
            addr: "127.0.0.1:9012".parse().unwrap(),
            denylist: IpFilter::none(),
            denylist_action: FilterAction::Ignore,
            allowlist: IpFilter::all(),
            allowlist_action: FilterAction::Ignore,
            rate_limiting_cutoff: Duration::from_millis(100),
            rate_limiting_cache_size: 32,
        };
        let (_, system_snapshots) = tokio::sync::watch::channel(SystemSnapshot::default());
        let clock = TestClock {};
        let (_, keyset) = tokio::sync::watch::channel(KeySetProvider::new(1).get());

        let server = ServerTask::spawn(
            config,
            Default::default(),
            system_snapshots,
            keyset,
            clock,
            InterfaceName::DEFAULT,
            Duration::from_secs(1),
        );

        let mut socket = UdpSocket::client(
            "127.0.0.1:9013".parse().unwrap(),
            "127.0.0.1:9012".parse().unwrap(),
        )
        .await
        .unwrap();

        let (packet, id) = NtpPacket::poll_message(PollIntervalLimits::default().min);

        let serialized = serialize_packet_unencryped(&packet);
        socket.send(&serialized).await.unwrap();

        let mut buf = [0; 48];
        tokio::time::timeout(Duration::from_millis(10), socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = NtpPacket::deserialize(&buf, &NoCipher).unwrap().0;
        assert_ne!(packet.stratum(), 0);
        assert!(packet.valid_server_response(id, false));

        tokio::time::sleep(std::time::Duration::from_millis(120)).await;

        let (packet, id) = NtpPacket::poll_message(PollIntervalLimits::default().min);

        let serialized = serialize_packet_unencryped(&packet);
        socket.send(&serialized).await.unwrap();

        let mut buf = [0; 48];
        tokio::time::timeout(Duration::from_millis(10), socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = NtpPacket::deserialize(&buf, &NoCipher).unwrap().0;
        assert_ne!(packet.stratum(), 0);
        assert!(packet.valid_server_response(id, false));

        let (packet, id) = NtpPacket::poll_message(PollIntervalLimits::default().min);

        let serialized = serialize_packet_unencryped(&packet);
        socket.send(&serialized).await.unwrap();

        let mut buf = [0; 48];
        tokio::time::timeout(Duration::from_millis(10), socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = NtpPacket::deserialize(&buf, &NoCipher).unwrap().0;
        assert_eq!(packet.stratum(), 0);
        assert_eq!(packet.reference_id(), ReferenceId::KISS_RATE);
        assert!(packet.valid_server_response(id, false));

        server.abort();
    }

    #[tokio::test]
    async fn test_server_rate_limit_defaults() {
        let config = ServerConfig {
            addr: "127.0.0.1:9014".parse().unwrap(),
            denylist: IpFilter::none(),
            denylist_action: FilterAction::Ignore,
            allowlist: IpFilter::all(),
            allowlist_action: FilterAction::Ignore,
            rate_limiting_cutoff: Duration::default(),
            rate_limiting_cache_size: Default::default(),
        };
        let (_, system_snapshots) = tokio::sync::watch::channel(SystemSnapshot::default());
        let clock = TestClock {};
        let (_, keyset) = tokio::sync::watch::channel(KeySetProvider::new(1).get());

        let server = ServerTask::spawn(
            config,
            Default::default(),
            system_snapshots,
            keyset,
            clock,
            InterfaceName::DEFAULT,
            Duration::from_secs(1),
        );

        let mut socket = UdpSocket::client(
            "127.0.0.1:9015".parse().unwrap(),
            "127.0.0.1:9014".parse().unwrap(),
        )
        .await
        .unwrap();

        let (packet, id) = NtpPacket::poll_message(PollIntervalLimits::default().min);

        let serialized = serialize_packet_unencryped(&packet);
        socket.send(&serialized).await.unwrap();

        let mut buf = [0; 48];
        tokio::time::timeout(Duration::from_millis(10), socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = NtpPacket::deserialize(&buf, &NoCipher).unwrap().0;
        assert_ne!(packet.stratum(), 0);
        assert!(packet.valid_server_response(id, false));

        server.abort();
    }
}

#[cfg(test)]
mod timestamped_cache {
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn timestamped_cache() {
        let length = 8u8;
        let mut cache: TimestampedCache<u8> = TimestampedCache::new(length as usize);

        let second = Duration::from_secs(1);
        let instant = Instant::now();

        assert!(cache.is_allowed(0, instant, second));

        assert!(!cache.is_allowed(0, instant, second));

        let later = instant + 2 * second;
        assert!(cache.is_allowed(0, later, second));

        // simulate a hash collision
        let even_later = later + 2 * second;
        assert!(cache.is_allowed(length, even_later, second));
    }

    #[test]
    fn timestamped_cache_size_0() {
        let mut cache = TimestampedCache::new(0);

        let second = Duration::from_secs(1);
        let instant = Instant::now();

        assert!(cache.is_allowed(0, instant, second));
    }
}
