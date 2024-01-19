use std::{
    collections::hash_map::RandomState,
    hash::BuildHasher,
    io::Cursor,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use ntp_proto::{
    Cipher, DecodedServerCookie, KeySet, NoCipher, NtpAssociationMode, NtpClock, NtpPacket,
    NtpTimestamp, PacketParsingError, SystemSnapshot,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use timestamped_socket::socket::{open_ip, Open, RecvResult, Socket};
use tokio::task::JoinHandle;
use tracing::{debug, instrument, trace, warn};

use super::{
    config::{FilterAction, ServerConfig},
    util::convert_net_timestamp,
};

// Maximum size of udp packet we handle
const MAX_PACKET_SIZE: usize = 1024;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ServerStats {
    pub received_packets: Counter,
    pub accepted_packets: Counter,
    pub denied_packets: Counter,
    pub ignored_packets: Counter,
    pub rate_limited_packets: Counter,
    pub response_send_errors: Counter,
    pub nts_received_packets: Counter,
    pub nts_accepted_packets: Counter,
    pub nts_denied_packets: Counter,
    pub nts_rate_limited_packets: Counter,
    pub nts_nak_packets: Counter,
}

impl ServerStats {
    fn update_from(&self, accept_result: &AcceptResult<'_>) {
        use AcceptResult::{Accept, CryptoNak, Deny, Ignore, RateLimit};

        self.received_packets.inc();

        match accept_result {
            Accept { .. } => self.accepted_packets.inc(),
            Ignore => self.ignored_packets.inc(),
            Deny { .. } => self.denied_packets.inc(),
            RateLimit { .. } => self.rate_limited_packets.inc(),
            CryptoNak { .. } => self.nts_nak_packets.inc(),
        };

        if accept_result.is_nts() {
            self.nts_received_packets.inc();
            match accept_result {
                Accept { .. } => self.nts_accepted_packets.inc(),
                Deny { .. } => self.nts_denied_packets.inc(),
                RateLimit { .. } => self.nts_rate_limited_packets.inc(),
                CryptoNak { .. } | Ignore => { /* counted above */ }
            };
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Counter {
    value: Arc<AtomicU64>,
}

impl Counter {
    fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.as_ref().load(Ordering::Relaxed)
    }
}

impl Serialize for Counter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.get())
    }
}

impl<'de> Deserialize<'de> for Counter {
    fn deserialize<D>(deserializer: D) -> Result<Counter, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Arc::new(Deserialize::deserialize(deserializer)?);
        Ok(Counter { value })
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
    stats: ServerStats,
}

#[derive(Debug)]
enum AcceptResult<'a> {
    Accept {
        packet: NtpPacket<'a>,
        decoded_cookie: Option<DecodedServerCookie>,
        recv_timestamp: NtpTimestamp,
    },
    Ignore,
    Deny {
        packet: NtpPacket<'a>,
        decoded_cookie: Option<DecodedServerCookie>,
    },
    RateLimit {
        packet: NtpPacket<'a>,
        decoded_cookie: Option<DecodedServerCookie>,
    },
    CryptoNak {
        packet: NtpPacket<'a>,
    },
}

impl AcceptResult<'_> {
    fn apply_deny(self) -> Self {
        // We should send deny messages only to reasonable requests
        // otherwise two servers could end up in a loop of sending
        // deny's to each other.
        match self {
            AcceptResult::Accept {
                packet,
                decoded_cookie,
                ..
            } => AcceptResult::Deny {
                packet,
                decoded_cookie,
            },
            other => other,
        }
    }

    fn apply_rate_limit(self) -> Self {
        match self {
            AcceptResult::Accept {
                packet,
                decoded_cookie,
                ..
            } => AcceptResult::RateLimit {
                packet,
                decoded_cookie,
            },
            other => other,
        }
    }

    fn is_nts(&self) -> bool {
        match self {
            AcceptResult::Accept { decoded_cookie, .. }
            | AcceptResult::Deny { decoded_cookie, .. }
            | AcceptResult::RateLimit { decoded_cookie, .. } => decoded_cookie.is_some(),
            AcceptResult::CryptoNak { .. } => true,
            AcceptResult::Ignore => false,
        }
    }

    fn kind_name(&self) -> &'static str {
        match self {
            AcceptResult::Accept { .. } => "Accept",
            AcceptResult::Ignore => "Ignore",
            AcceptResult::Deny { .. } => "Deny",
            AcceptResult::RateLimit { .. } => "RateLimit",
            AcceptResult::CryptoNak { .. } => "CryptoNak",
        }
    }
}

#[must_use]
#[derive(Debug, Clone, Copy)]
enum SocketConnection {
    KeepAlive,
    Reconnect,
}

enum FilterReason {
    Deny,
    Ignore,
    RateLimit,
}

impl<C: 'static + NtpClock + Send> ServerTask<C> {
    pub fn spawn(
        config: ServerConfig,
        stats: ServerStats,
        mut system_receiver: tokio::sync::watch::Receiver<SystemSnapshot>,
        keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
        clock: C,
        network_wait_period: Duration,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let rate_limiting_cache_size = config.rate_limiting_cache_size;
            let system: SystemSnapshot = *system_receiver.borrow_and_update();

            let mut process = ServerTask {
                config,
                network_wait_period,
                system,
                system_receiver,
                keyset,
                clock,
                client_cache: TimestampedCache::new(rate_limiting_cache_size),
                stats,
            };

            process.serve().await;
        })
    }

    fn filter(&self, addr: &IpAddr) -> Option<FilterAction> {
        if self.config.denylist.filter.is_in(addr) {
            // First apply denylist
            Some(self.config.denylist.action)
        } else if !self.config.allowlist.filter.is_in(addr) {
            // Then allowlist
            Some(self.config.allowlist.action)
        } else {
            None
        }
    }

    #[instrument(level = "debug", skip(self), fields(
        addr = debug(self.config.listen),
    ))]
    async fn serve(&mut self) {
        let mut cur_socket = None;
        loop {
            // open socket if it is not already open
            let socket = match &mut cur_socket {
                Some(socket) => socket,
                None => {
                    let new_socket = loop {
                        let socket_res = open_ip(
                            self.config.listen,
                            timestamped_socket::socket::GeneralTimestampMode::SoftwareRecv,
                        );

                        match socket_res {
                            Ok(socket) => break socket,
                            Err(error) => {
                                warn!(?error, ?self.config.listen, "Could not open server socket");
                                tokio::time::sleep(self.network_wait_period).await;
                            }
                        }
                    };

                    // system may now be wildly out of date, ensure it is always updated.
                    self.system = *self.system_receiver.borrow_and_update();

                    cur_socket.insert(new_socket)
                }
            };

            let mut buf = [0_u8; MAX_PACKET_SIZE];
            tokio::select! {
                recv_res = socket.recv(&mut buf) => {
                    match self.handle_receive(socket, &buf, recv_res).await {
                        SocketConnection::KeepAlive => { /* do nothing */ }
                        SocketConnection::Reconnect => { cur_socket = None }
                    }
                },
                _ = self.system_receiver.changed(), if self.system_receiver.has_changed().is_ok() => {
                    self.system = *self.system_receiver.borrow_and_update();
                }
            }
        }
    }

    /// Checks if the address of the sender is on the allow or deny list and if the address already
    /// did perform a request within the last `cutoff` interval
    fn check_and_update_filters(
        &mut self,
        peer_addr: SocketAddr,
        cutoff: Duration,
    ) -> Result<(), FilterReason> {
        match self.filter(&peer_addr.ip()) {
            Some(FilterAction::Deny) => Err(FilterReason::Deny),
            Some(FilterAction::Ignore) => Err(FilterReason::Ignore),
            None => {
                let now = Instant::now();
                if self.client_cache.is_allowed(peer_addr.ip(), now, cutoff) {
                    Ok(())
                } else {
                    Err(FilterReason::RateLimit)
                }
            }
        }
    }

    /// Handle the result of the `recv` call
    /// - decide if an IO error warrants reopening the socket
    /// - check if the sender address matches any of the allow, deny, or rate-limit filters
    ///
    /// -> call [`Self::generate_response`] to further process the packet
    async fn handle_receive(
        &mut self,
        socket: &mut Socket<SocketAddr, Open>,
        buf: &[u8],
        recv_res: std::io::Result<RecvResult<SocketAddr>>,
    ) -> SocketConnection {
        match recv_res {
            Err(receive_error) => {
                warn!(?receive_error, "could not receive packet");

                // For a server, we only trigger NetworkGone restarts
                // on ENETDOWN. ENETUNREACH, EHOSTDOWN and EHOSTUNREACH
                // do not signal restart-worthy conditions for the a
                // server (they essentially indicate problems with the
                // remote network/host, which is not relevant for a server).
                // Furthermore, they can conceivably be triggered by a
                // malicious third party, and triggering restart on them
                // would then result in a denial-of-service.
                match receive_error.raw_os_error() {
                    Some(libc::ENETDOWN) => SocketConnection::Reconnect,
                    _ => {
                        self.stats.ignored_packets.inc();
                        SocketConnection::KeepAlive
                    }
                }
            }
            Ok(RecvResult {
                bytes_read: length,
                remote_addr: peer_addr,
                timestamp: opt_timestamp,
            }) => {
                let Some(request_buf) = buf.get(..length) else {
                    warn!("length from socket is out of bounds. This is a bug!");
                    return SocketConnection::Reconnect;
                };

                // The response buffer gets the same size as the request was so we can never send
                // a response that is longer than the request
                let mut response_buf = [0; MAX_PACKET_SIZE];
                let response_buf = &mut response_buf[..length];

                let Some(response) = self.handle_packet(
                    request_buf,
                    response_buf,
                    peer_addr,
                    opt_timestamp.map(convert_net_timestamp),
                ) else {
                    return SocketConnection::KeepAlive;
                };

                if let Err(send_err) = socket.send_to(response, peer_addr).await {
                    self.stats.response_send_errors.inc();
                    debug!(error=?send_err, "Could not send response packet");
                }

                SocketConnection::KeepAlive
            }
        }
    }

    #[instrument(level = "debug", skip_all, fields(peer_addr, size = request_buf.len(), opt_timestamp))]
    fn handle_packet<'buf>(
        &mut self,
        request_buf: &[u8],
        response_buf: &'buf mut [u8],
        peer_addr: SocketAddr,
        opt_timestamp: Option<NtpTimestamp>,
    ) -> Option<&'buf [u8]> {
        let Some(timestamp) = opt_timestamp else {
            debug!("received a packet without a timestamp");
            self.stats.update_from(&AcceptResult::Ignore);
            return None;
        };

        // Note: packets are allowed to be bigger when including extensions.
        // we don't expect many, but the client may still send them. We try
        // to see if the message still makes sense with some bytes dropped.
        // Messages of fewer than 48 bytes are skipped entirely
        if request_buf.len() < 48 {
            debug!("received packet is too small");
            self.stats.update_from(&AcceptResult::Ignore);
            return None;
        }

        let filter_result =
            self.check_and_update_filters(peer_addr, self.config.rate_limiting_cutoff);
        if let Err(FilterReason::Ignore) = filter_result {
            debug!("filters decided to ignore");
            self.stats.update_from(&AcceptResult::Ignore);
            return None;
        }

        // actually parse the packet. KeySet is cloned to not take a lock
        let keyset = self.keyset.borrow().clone();
        let accept_result = Self::accept_data(request_buf, keyset.as_ref(), timestamp);

        // apply filters
        let accept_result = match filter_result {
            Ok(_) => accept_result,
            Err(FilterReason::Ignore) => AcceptResult::Ignore,
            Err(FilterReason::Deny) => accept_result.apply_deny(),
            Err(FilterReason::RateLimit) => accept_result.apply_rate_limit(),
        };

        // update statistics
        self.stats.update_from(&accept_result);
        debug!(kind = accept_result.kind_name(), "Decided response");

        let (packet, opt_cipher) = self.generate_response(accept_result)?;
        let response_buf = Self::serialize_response(response_buf, packet, opt_cipher)?;

        debug!(response_size = response_buf.len(), "Generated response");

        Some(response_buf)
    }

    fn generate_response<'a>(
        &self,
        accept_result: AcceptResult<'a>,
    ) -> Option<(NtpPacket<'a>, Option<Box<dyn Cipher>>)> {
        let (packet, cipher) = match accept_result {
            AcceptResult::Ignore => {
                return None;
            }

            AcceptResult::Accept {
                packet,
                decoded_cookie,
                recv_timestamp,
            } => match decoded_cookie {
                Some(cookie) => {
                    let keyset = self.keyset.borrow().clone();
                    let response = NtpPacket::nts_timestamp_response(
                        &self.system,
                        packet,
                        recv_timestamp,
                        &self.clock,
                        &cookie,
                        &keyset,
                    );
                    (response, Some(cookie.s2c))
                }
                None => (
                    NtpPacket::timestamp_response(
                        &self.system,
                        packet,
                        recv_timestamp,
                        &self.clock,
                    ),
                    None,
                ),
            },

            AcceptResult::CryptoNak { packet } => (NtpPacket::nts_nak_response(packet), None),

            AcceptResult::Deny {
                packet,
                decoded_cookie,
            } => match decoded_cookie {
                Some(cookie) => (NtpPacket::nts_deny_response(packet), Some(cookie.s2c)),
                None => (NtpPacket::deny_response(packet), None),
            },

            AcceptResult::RateLimit {
                packet,
                decoded_cookie,
            } => match decoded_cookie {
                Some(cookie) => (NtpPacket::nts_rate_limit_response(packet), Some(cookie.s2c)),
                None => (NtpPacket::rate_limit_response(packet), None),
            },
        };

        Some((packet, cipher))
    }

    /// Build a response to the given packet
    fn serialize_response<'buf>(
        response_buf: &'buf mut [u8],
        packet: NtpPacket<'_>,
        opt_cipher: Option<Box<dyn Cipher>>,
    ) -> Option<&'buf [u8]> {
        let desired_size = match packet.version() {
            5 => Some(response_buf.len()),
            _ => None,
        };
        let mut cursor = Cursor::new(response_buf);

        let serialize_result = match opt_cipher {
            Some(cipher) => packet.serialize(&mut cursor, cipher.as_ref(), desired_size),
            None => packet.serialize(&mut cursor, &NoCipher, desired_size),
        };

        if let Err(serialize_err) = serialize_result {
            warn!(error=?serialize_err, "Could not serialize response");
            return None;
        }

        let end = usize::try_from(cursor.position()).expect(concat!(
            "cursor.position() is always less then usize::MAX, ",
            "since &[u8] can be at most usize::MAX bytes",
        ));
        let response_buf = cursor.into_inner();

        Some(&response_buf[..end])
    }

    /// Deserialize the packet and decide what our response should be
    /// - check if the packet can even be deserialized
    /// - check if it was successfully decrypted (and authenticated)
    /// - check if it was a request packet (`Client` prior to NTPv5)
    fn accept_data<'a>(
        buf: &'a [u8],
        keyset: &KeySet,
        recv_timestamp: NtpTimestamp,
    ) -> AcceptResult<'a> {
        match NtpPacket::deserialize(buf, keyset) {
            Ok((packet, decoded_cookie)) => match packet.mode() {
                NtpAssociationMode::Client => {
                    trace!("NTP client request accepted");
                    AcceptResult::Accept {
                        packet,
                        decoded_cookie,
                        recv_timestamp,
                    }
                }
                _ => {
                    trace!("NTP packet with unknown mode {:?} ignored", packet.mode());
                    AcceptResult::Ignore
                }
            },
            Err(PacketParsingError::DecryptError(packet)) => {
                debug!("received packet with invalid nts cookie");
                AcceptResult::CryptoNak { packet }
            }
            Err(e) => {
                debug!("received invalid packet: {e}");
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
        KeySetProvider, NoCipher, NtpDuration, NtpLeapIndicator, PollInterval, PollIntervalLimits,
        ReferenceId,
    };
    use timestamped_socket::socket::GeneralTimestampMode;

    use crate::daemon::config::FilterList;

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

        fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
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

    fn serialize_packet_unencryped(send_packet: &NtpPacket) -> Vec<u8> {
        let mut buf = vec![0; MAX_PACKET_SIZE];
        let mut cursor = Cursor::new(buf.as_mut_slice());
        send_packet.serialize(&mut cursor, &NoCipher, None).unwrap();

        let end = cursor.position() as usize;
        buf.truncate(end);
        buf
    }

    fn default_server_task() -> ServerTask<TestClock> {
        let config = ServerConfig {
            listen: "127.0.0.1:9000".parse().unwrap(),
            denylist: FilterList::default_denylist(),
            allowlist: FilterList::default_allowlist(),
            rate_limiting_cutoff: Duration::from_secs(0),
            rate_limiting_cache_size: 32,
        };
        let (_, mut system_snapshots) = tokio::sync::watch::channel(SystemSnapshot::default());
        let clock = TestClock {};
        let (_, keyset) = tokio::sync::watch::channel(KeySetProvider::new(1).get());
        let rate_limiting_cache_size = config.rate_limiting_cache_size;
        let system: SystemSnapshot = *system_snapshots.borrow_and_update();

        ServerTask {
            config,
            network_wait_period: Default::default(),
            keyset,
            system,
            system_receiver: system_snapshots,
            client_cache: TimestampedCache::new(rate_limiting_cache_size),
            clock,
            stats: Default::default(),
        }
    }

    #[tokio::test]
    async fn test_server_filter_allow_ok() {
        let config = ServerConfig {
            listen: "127.0.0.1:9000".parse().unwrap(),
            denylist: FilterList::default_denylist(),
            allowlist: FilterList::new(&["127.0.0.0/24".parse().unwrap()], FilterAction::Ignore),
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
            Duration::from_secs(1),
        );

        let socket = open_ip(
            "127.0.0.1:9001".parse().unwrap(),
            GeneralTimestampMode::SoftwareRecv,
        )
        .unwrap();
        let mut socket = socket.connect("127.0.0.1:9000".parse().unwrap()).unwrap();
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
            listen: "127.0.0.1:9002".parse().unwrap(),
            denylist: FilterList::default_denylist(),
            allowlist: FilterList::new(&["128.0.0.0/24".parse().unwrap()], FilterAction::Deny),
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
            Duration::from_secs(1),
        );

        let socket = open_ip(
            "127.0.0.1:9003".parse().unwrap(),
            GeneralTimestampMode::SoftwareRecv,
        )
        .unwrap();
        let mut socket = socket.connect("127.0.0.1:9002".parse().unwrap()).unwrap();
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
            listen: "127.0.0.1:9004".parse().unwrap(),
            denylist: FilterList::default_denylist(),
            allowlist: FilterList::new(&["128.0.0.0/24".parse().unwrap()], FilterAction::Ignore),
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
            Duration::from_secs(1),
        );

        let socket = open_ip(
            "127.0.0.1:9005".parse().unwrap(),
            GeneralTimestampMode::SoftwareRecv,
        )
        .unwrap();
        let mut socket = socket.connect("127.0.0.1:9004".parse().unwrap()).unwrap();
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
            listen: "127.0.0.1:9006".parse().unwrap(),
            denylist: FilterList::new(&["192.168.0.0/16".parse().unwrap()], FilterAction::Ignore),
            allowlist: FilterList::default_allowlist(),
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
            Duration::from_secs(1),
        );

        let socket = open_ip(
            "127.0.0.1:9007".parse().unwrap(),
            GeneralTimestampMode::SoftwareRecv,
        )
        .unwrap();
        let mut socket = socket.connect("127.0.0.1:9006".parse().unwrap()).unwrap();
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
            listen: "127.0.0.1:9008".parse().unwrap(),
            denylist: FilterList::new(&["127.0.0.0/24".parse().unwrap()], FilterAction::Deny),
            allowlist: FilterList::default_allowlist(),
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
            Duration::from_secs(1),
        );

        let socket = open_ip(
            "127.0.0.1:9009".parse().unwrap(),
            GeneralTimestampMode::SoftwareRecv,
        )
        .unwrap();
        let mut socket = socket.connect("127.0.0.1:9008".parse().unwrap()).unwrap();
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
            listen: "127.0.0.1:9010".parse().unwrap(),
            denylist: FilterList::new(&["127.0.0.0/24".parse().unwrap()], FilterAction::Ignore),
            allowlist: FilterList::default_allowlist(),
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
            Duration::from_secs(1),
        );

        let socket = open_ip(
            "127.0.0.1:9011".parse().unwrap(),
            GeneralTimestampMode::SoftwareRecv,
        )
        .unwrap();
        let mut socket = socket.connect("127.0.0.1:9010".parse().unwrap()).unwrap();
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
            listen: "127.0.0.1:9012".parse().unwrap(),
            denylist: FilterList::default_denylist(),
            allowlist: FilterList::default_allowlist(),
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
            Duration::from_secs(1),
        );

        let socket = open_ip(
            "127.0.0.1:9013".parse().unwrap(),
            GeneralTimestampMode::SoftwareRecv,
        )
        .unwrap();
        let mut socket = socket.connect("127.0.0.1:9012".parse().unwrap()).unwrap();

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
            listen: "127.0.0.1:9014".parse().unwrap(),
            denylist: FilterList::default_denylist(),
            allowlist: FilterList::default_allowlist(),
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
            Duration::from_secs(1),
        );

        let socket = open_ip(
            "127.0.0.1:9015".parse().unwrap(),
            GeneralTimestampMode::SoftwareRecv,
        )
        .unwrap();
        let mut socket = socket.connect("127.0.0.1:9014".parse().unwrap()).unwrap();

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

    #[test]
    fn test_handle_v4_packet() {
        let mut server = default_server_task();
        let mut response_buf = [0; MAX_PACKET_SIZE];
        let timestamp = NtpTimestamp::from_seconds_nanos_since_ntp_era(1, 0);

        let (packet, id) = NtpPacket::poll_message(PollIntervalLimits::default().min);
        let serialized = serialize_packet_unencryped(&packet);

        let response = server
            .handle_packet(
                &serialized,
                response_buf.as_mut_slice(),
                "127.0.0.1:9001".parse().unwrap(),
                Some(timestamp),
            )
            .unwrap();

        let response = NtpPacket::deserialize(response, &NoCipher).unwrap().0;

        assert_eq!(response.version(), 4);
        assert_eq!(response.stratum(), 16);
        assert!(response.valid_server_response(id, false));
        assert!(response.transmit_timestamp() != NtpTimestamp::default());
        assert_eq!(response.receive_timestamp(), timestamp);

        let (packet, _id) = NtpPacket::poll_message(PollIntervalLimits::default().min);
        let mut serialized = serialize_packet_unencryped(&packet);

        // corrupt the package
        serialized[0] = 42;

        let response = server.handle_packet(
            &serialized,
            response_buf.as_mut_slice(),
            "127.0.0.1:9001".parse().unwrap(),
            Some(timestamp),
        );

        assert_eq!(response, None);
    }

    #[cfg(feature = "unstable_ntpv5")]
    #[test]
    fn test_handle_v5_packet() {
        let mut server = default_server_task();
        let mut response_buf = [0; MAX_PACKET_SIZE];
        let timestamp = NtpTimestamp::from_seconds_nanos_since_ntp_era(1, 0);

        let (packet, id) = NtpPacket::poll_message_v5(PollIntervalLimits::default().min);
        let serialized = serialize_packet_unencryped(&packet);

        let response = server
            .handle_packet(
                &serialized,
                &mut response_buf[..serialized.len()],
                "127.0.0.1:9001".parse().unwrap(),
                Some(timestamp),
            )
            .unwrap();

        let response = NtpPacket::deserialize(response, &NoCipher).unwrap().0;

        assert_eq!(response.version(), 5);
        assert_eq!(response.stratum(), 16);
        assert!(response.valid_server_response(id, false));
        assert!(response.transmit_timestamp() != NtpTimestamp::default());
        assert_eq!(response.receive_timestamp(), timestamp);

        let (packet, _id) = NtpPacket::poll_message_v5(PollIntervalLimits::default().min);
        let mut serialized = serialize_packet_unencryped(&packet);

        // corrupt the package
        serialized[0] = 42;

        let response = server.handle_packet(
            &serialized,
            response_buf.as_mut_slice(),
            "127.0.0.1:9001".parse().unwrap(),
            Some(timestamp),
        );

        assert_eq!(response, None);
    }

    #[test]
    fn early_fails() {
        let mut s = default_server_task();
        let mut resp_buf = [0; MAX_PACKET_SIZE];

        let (req, _) = NtpPacket::poll_message(PollInterval::default());
        let req = serialize_packet_unencryped(&req);

        // No timestamp
        s.stats = ServerStats::default();
        assert_eq!(
            s.handle_packet(
                req.as_slice(),
                &mut resp_buf,
                "127.0.0.1:1337".parse().unwrap(),
                None,
            ),
            None
        );
        assert_eq!(s.stats.ignored_packets.get(), 1);
        assert_eq!(s.stats.received_packets.get(), 1);

        // Too short
        s.stats = ServerStats::default();
        assert!(s
            .handle_packet(
                &[0; 23],
                &mut resp_buf,
                "127.0.0.1:1337".parse().unwrap(),
                Some(NtpTimestamp::default()),
            )
            .is_none());
        assert_eq!(s.stats.ignored_packets.get(), 1);
        assert_eq!(s.stats.received_packets.get(), 1);
    }

    #[test]
    fn invalid_packet() {
        let mut s = default_server_task();
        let mut resp_buf = [0; MAX_PACKET_SIZE];

        let (req, _) = NtpPacket::poll_message(PollInterval::default());
        let mut req = serialize_packet_unencryped(&req);
        req[0] = 0;

        assert!(s
            .handle_packet(
                &req,
                &mut resp_buf,
                "127.0.0.1:1337".parse().unwrap(),
                Some(NtpTimestamp::default()),
            )
            .is_none());
        assert_eq!(s.stats.ignored_packets.get(), 1);
        assert_eq!(s.stats.received_packets.get(), 1);
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
