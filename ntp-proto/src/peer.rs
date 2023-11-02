#[cfg(feature = "ntpv5")]
use crate::packet::{
    v5::server_reference_id::{BloomFilter, RemoteBloomFilter},
    ExtensionField, NtpHeader,
};
use crate::{
    config::SourceDefaultsConfig,
    cookiestash::CookieStash,
    identifiers::ReferenceId,
    packet::{Cipher, NtpAssociationMode, NtpLeapIndicator, NtpPacket, RequestIdentifier},
    system::SystemSnapshot,
    time_types::{NtpDuration, NtpInstant, NtpTimestamp, PollInterval},
};
use serde::{Deserialize, Serialize};
use std::{io::Cursor, net::SocketAddr};
use tracing::{debug, info, instrument, trace, warn};

const MAX_STRATUM: u8 = 16;
const POLL_WINDOW: std::time::Duration = std::time::Duration::from_secs(5);
const STARTUP_TRIES_THRESHOLD: usize = 3;

#[derive(Debug, thiserror::Error)]
pub enum NtsError {
    #[error("Ran out of nts cookies")]
    OutOfCookies,
}

pub struct PeerNtsData {
    pub(crate) cookies: CookieStash,
    // Note: we use Box<dyn Cipher> to support the use
    // of multiple different ciphers, that might differ
    // in the key information they need to keep.
    pub(crate) c2s: Box<dyn Cipher>,
    pub(crate) s2c: Box<dyn Cipher>,
}

#[cfg(feature = "__internal-test")]
impl PeerNtsData {
    pub fn get_cookie(&mut self) -> Option<Vec<u8>> {
        self.cookies.get()
    }

    pub fn get_keys(self) -> (Box<dyn Cipher>, Box<dyn Cipher>) {
        (self.c2s, self.s2c)
    }
}

impl std::fmt::Debug for PeerNtsData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerNtsData")
            .field("cookies", &self.cookies)
            .finish()
    }
}

#[derive(Debug)]
pub struct Peer {
    nts: Option<Box<PeerNtsData>>,

    // Poll interval dictated by unreachability backoff
    backoff_interval: PollInterval,
    // Poll interval used when sending last poll mesage.
    last_poll_interval: PollInterval,
    // The poll interval desired by the remove server.
    // Must be increased when the server sends the RATE kiss code.
    remote_min_poll_interval: PollInterval,

    // Identifier of the last request sent to the server. This is correlated
    // with any received response from the server to guard against replay
    // attacks and packet reordering.
    current_request_identifier: Option<(RequestIdentifier, NtpInstant)>,

    stratum: u8,
    reference_id: ReferenceId,

    source_addr: SocketAddr,
    source_id: ReferenceId,
    our_id: ReferenceId,
    reach: Reach,
    tries: usize,

    peer_defaults_config: SourceDefaultsConfig,

    protocol_version: ProtocolVersion,

    #[cfg(feature = "ntpv5")]
    bloom_filter: Option<RemoteBloomFilter>,
}

#[derive(Debug, Copy, Clone)]
pub struct Measurement {
    pub delay: NtpDuration,
    pub offset: NtpDuration,
    pub transmit_timestamp: NtpTimestamp,
    pub receive_timestamp: NtpTimestamp,
    pub localtime: NtpTimestamp,
    pub monotime: NtpInstant,

    pub stratum: u8,
    pub root_delay: NtpDuration,
    pub root_dispersion: NtpDuration,
    pub leap: NtpLeapIndicator,
    pub precision: i8,
}

impl Measurement {
    fn from_packet(
        packet: &NtpPacket,
        send_timestamp: NtpTimestamp,
        recv_timestamp: NtpTimestamp,
        local_clock_time: NtpInstant,
        precision: NtpDuration,
    ) -> Self {
        Self {
            delay: ((recv_timestamp - send_timestamp)
                - (packet.transmit_timestamp() - packet.receive_timestamp()))
            .max(precision),
            offset: ((packet.receive_timestamp() - send_timestamp)
                + (packet.transmit_timestamp() - recv_timestamp))
                / 2,
            transmit_timestamp: packet.transmit_timestamp(),
            receive_timestamp: packet.receive_timestamp(),
            localtime: send_timestamp + (recv_timestamp - send_timestamp) / 2,
            monotime: local_clock_time,

            stratum: packet.stratum(),
            root_delay: packet.root_delay(),
            root_dispersion: packet.root_dispersion(),
            leap: packet.leap(),
            precision: packet.precision(),
        }
    }
}

/// Used to determine whether the server is reachable and the data are fresh
///
/// This value is represented as an 8-bit shift register. The register is shifted left
/// by one bit when a packet is sent and the rightmost bit is set to zero.
/// As valid packets arrive, the rightmost bit is set to one.
/// If the register contains any nonzero bits, the server is considered reachable;
/// otherwise, it is unreachable.
#[derive(Default, Clone, Copy, Serialize, Deserialize)]
pub struct Reach(u8);

impl std::fmt::Debug for Reach {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_reachable() {
            write!(
                f,
                "Reach(0b{:07b} ({} polls until unreachable))",
                self.0,
                7 - self.0.trailing_zeros()
            )
        } else {
            write!(f, "Reach(unreachable)",)
        }
    }
}

impl Reach {
    pub fn is_reachable(&self) -> bool {
        self.0 != 0
    }

    /// We have just received a packet, so the peer is definitely reachable
    pub(crate) fn received_packet(&mut self) {
        self.0 |= 1;
    }

    /// A packet received some number of poll intervals ago is decreasingly relevant for
    /// determining that a peer is still reachable. We discount the packets received so far.
    fn poll(&mut self) {
        self.0 <<= 1;
    }

    /// Number of polls since the last message we received
    pub fn unanswered_polls(&self) -> u32 {
        self.0.trailing_zeros()
    }
}

#[derive(Debug)]
pub enum IgnoreReason {
    /// The packet doesn't parse
    InvalidPacket,
    /// The association mode is not one that this peer supports
    InvalidMode,
    /// The NTP version is not one that this implementation supports
    InvalidVersion,
    /// The stratum of the server is too high
    InvalidStratum,
    /// The send time on the received packet is not the time we sent it at
    InvalidPacketTime,
    /// Received a Kiss-o'-Death https://datatracker.ietf.org/doc/html/rfc5905#section-7.4
    KissIgnore,
    /// Received a DENY or RSTR Kiss-o'-Death, and must demobilize the association
    KissDemobilize,
    /// Received a matching NTS-Nack, no further action needed.
    KissNtsNack,
    /// The best packet is older than the peer's current time
    TooOld,
}

#[derive(Debug, Clone, Copy)]
pub struct PeerSnapshot {
    pub source_addr: SocketAddr,

    pub source_id: ReferenceId,
    pub our_id: ReferenceId,

    pub poll_interval: PollInterval,
    pub reach: Reach,

    pub stratum: u8,
    pub reference_id: ReferenceId,

    #[cfg(feature = "ntpv5")]
    pub bloom_filter: Option<BloomFilter>,
}

impl PeerSnapshot {
    pub fn accept_synchronization(
        &self,
        local_stratum: u8,
        system: &SystemSnapshot,
    ) -> Result<(), AcceptSynchronizationError> {
        use AcceptSynchronizationError::*;

        if self.stratum >= local_stratum {
            info!(
                peer_stratum = self.stratum,
                own_stratum = local_stratum,
                "Peer rejected due to invalid stratum. The stratum of a peer must be lower than the own stratum",
            );
            return Err(Stratum);
        }

        // Detect whether the remote uses us as their main time reference.
        // if so, we shouldn't sync to them as that would create a loop.
        // Note, this can only ever be an issue if the peer is not using
        // hardware as its source, so ignore reference_id if stratum is 1.
        if self.stratum != 1 && self.reference_id == self.our_id {
            info!("Peer rejected because of detected synchronization loop (ref id)");
            return Err(Loop);
        }

        #[cfg(feature = "ntpv5")]
        match self.bloom_filter {
            Some(filter) if filter.contains_id(&system.server_id) => {
                info!("Peer rejected because of detected synchronization loop (bloom filter)");
                return Err(Loop);
            }
            _ => {}
        }

        // An unreachable error occurs if the server is unreachable.
        if !self.reach.is_reachable() {
            info!("Peer is unreachable");
            return Err(ServerUnreachable);
        }

        Ok(())
    }

    pub fn from_peer(peer: &Peer) -> Self {
        Self {
            source_addr: peer.source_addr,
            source_id: peer.source_id,
            our_id: peer.our_id,
            stratum: peer.stratum,
            reference_id: peer.reference_id,
            reach: peer.reach,
            poll_interval: peer.last_poll_interval,
            #[cfg(feature = "ntpv5")]
            bloom_filter: peer
                .bloom_filter
                .as_ref()
                .and_then(|bf| bf.full_filter().copied()),
        }
    }
}

#[cfg(feature = "__internal-test")]
pub fn peer_snapshot() -> PeerSnapshot {
    use std::net::{IpAddr, Ipv4Addr};

    let mut reach = crate::peer::Reach::default();
    reach.received_packet();

    PeerSnapshot {
        source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        source_id: ReferenceId::from_int(0),
        stratum: 0,
        reference_id: ReferenceId::from_int(0),

        our_id: ReferenceId::from_int(1),
        reach,
        poll_interval: crate::time_types::PollIntervalLimits::default().min,
        #[cfg(feature = "ntpv5")]
        bloom_filter: None,
    }
}

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AcceptSynchronizationError {
    ServerUnreachable,
    Loop,
    Distance,
    Stratum,
}

#[derive(Debug)]
pub enum Update {
    BareUpdate(PeerSnapshot),
    NewMeasurement(PeerSnapshot, Measurement),
}

#[derive(Debug, thiserror::Error)]
pub enum PollError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("peer unreachable")]
    PeerUnreachable,
}

#[derive(Debug, Copy, Clone)]
pub enum ProtocolVersion {
    V4,
    #[cfg(feature = "ntpv5")]
    V4UpgradingToV5 {
        tries_left: u8,
    },
    #[cfg(feature = "ntpv5")]
    V5,
}

impl ProtocolVersion {
    pub fn expected_incoming_version(&self) -> u8 {
        match self {
            ProtocolVersion::V4 => 4,
            #[cfg(feature = "ntpv5")]
            ProtocolVersion::V4UpgradingToV5 { .. } => 4,
            #[cfg(feature = "ntpv5")]
            ProtocolVersion::V5 => 5,
        }
    }
}

impl Default for ProtocolVersion {
    #[cfg(feature = "ntpv5")]
    fn default() -> Self {
        Self::V4UpgradingToV5 { tries_left: 8 }
    }

    #[cfg(not(feature = "ntpv5"))]
    fn default() -> Self {
        Self::V4
    }
}

impl Peer {
    #[instrument]
    pub fn new(
        our_addr: SocketAddr,
        source_addr: SocketAddr,
        local_clock_time: NtpInstant,
        peer_defaults_config: SourceDefaultsConfig,
    ) -> Self {
        Self {
            nts: None,

            last_poll_interval: peer_defaults_config.poll_interval_limits.min,
            backoff_interval: peer_defaults_config.poll_interval_limits.min,
            remote_min_poll_interval: peer_defaults_config.poll_interval_limits.min,

            current_request_identifier: None,
            our_id: ReferenceId::from_ip(our_addr.ip()),
            source_id: ReferenceId::from_ip(source_addr.ip()),
            source_addr,
            reach: Default::default(),
            tries: 0,

            stratum: 16,
            reference_id: ReferenceId::NONE,

            peer_defaults_config,

            protocol_version: Default::default(), // TODO make this configurable

            #[cfg(feature = "ntpv5")]
            bloom_filter: None,
        }
    }

    #[instrument]
    pub fn new_nts(
        our_addr: SocketAddr,
        source_addr: SocketAddr,
        local_clock_time: NtpInstant,
        peer_defaults_config: SourceDefaultsConfig,
        nts: Box<PeerNtsData>,
    ) -> Self {
        Self {
            nts: Some(nts),
            ..Self::new(
                our_addr,
                source_addr,
                local_clock_time,
                peer_defaults_config,
            )
        }
    }

    pub fn update_config(&mut self, peer_defaults_config: SourceDefaultsConfig) {
        self.peer_defaults_config = peer_defaults_config;
    }

    pub fn current_poll_interval(&self, system: SystemSnapshot) -> PollInterval {
        system
            .time_snapshot
            .poll_interval
            .max(self.backoff_interval)
            .max(self.remote_min_poll_interval)
    }

    #[cfg_attr(not(feature = "ntpv5"), allow(unused_mut))]
    pub fn generate_poll_message<'a>(
        &mut self,
        buf: &'a mut [u8],
        system: SystemSnapshot,
        peer_defaults_config: &SourceDefaultsConfig,
    ) -> Result<&'a [u8], PollError> {
        if !self.reach.is_reachable() && self.tries >= STARTUP_TRIES_THRESHOLD {
            return Err(PollError::PeerUnreachable);
        }

        self.reach.poll();
        self.tries = self.tries.saturating_add(1);

        let poll_interval = self.current_poll_interval(system);
        let (mut packet, identifier) = match &mut self.nts {
            Some(nts) => {
                let cookie = nts.cookies.get().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::Other, NtsError::OutOfCookies)
                })?;
                // Do ensure we don't exceed the buffer size
                // when requesting new cookies. We keep 350
                // bytes of margin for header, ids, extension
                // field headers and signature.
                let new_cookies = nts
                    .cookies
                    .gap()
                    .min(((buf.len() - 300) / cookie.len()).min(u8::MAX as usize) as u8);
                NtpPacket::nts_poll_message(&cookie, new_cookies, poll_interval)
            }
            None => match self.protocol_version {
                ProtocolVersion::V4 => NtpPacket::poll_message(poll_interval),
                #[cfg(feature = "ntpv5")]
                ProtocolVersion::V4UpgradingToV5 { .. } => {
                    NtpPacket::poll_message_upgrade_request(poll_interval)
                }
                #[cfg(feature = "ntpv5")]
                ProtocolVersion::V5 => NtpPacket::poll_message_v5(poll_interval),
            },
        };
        self.current_request_identifier = Some((identifier, NtpInstant::now() + POLL_WINDOW));

        // Ensure we don't spam the remote with polls if it is not reachable
        self.backoff_interval = poll_interval.inc(peer_defaults_config.poll_interval_limits);

        #[cfg(feature = "ntpv5")]
        if let NtpHeader::V5(header) = packet.header() {
            if let Some(ref mut filter) = self.bloom_filter {
                let req_ef = filter.next_request(header.client_cookie);
                packet.push_untrusted(ExtensionField::ReferenceIdRequest(req_ef));
            }
        }

        // Write packet to buffer
        let mut cursor = Cursor::new(buf);
        packet.serialize(
            &mut cursor,
            &self.nts.as_ref().map(|nts| nts.c2s.as_ref()),
            None,
        )?;
        let used = cursor.position();
        let result = &cursor.into_inner()[..used as usize];

        // update the poll interval
        self.last_poll_interval = poll_interval;

        Ok(result)
    }

    #[instrument(skip(self, system), fields(peer = debug(self.source_id)))]
    pub fn handle_incoming(
        &mut self,
        system: SystemSnapshot,
        message: &[u8],
        local_clock_time: NtpInstant,
        send_time: NtpTimestamp,
        recv_time: NtpTimestamp,
    ) -> Result<Update, IgnoreReason> {
        let message =
            match NtpPacket::deserialize(message, &self.nts.as_ref().map(|nts| nts.s2c.as_ref())) {
                Ok((packet, _)) => packet,
                Err(e) => {
                    warn!("received invalid packet: {}", e);
                    return Err(IgnoreReason::InvalidPacket);
                }
            };

        if message.version() != self.protocol_version.expected_incoming_version() {
            return Err(IgnoreReason::InvalidVersion);
        }

        let request_identifier = match self.current_request_identifier {
            Some((next_expected_origin, validity)) if validity >= NtpInstant::now() => {
                next_expected_origin
            }
            _ => {
                debug!("Received old/unexpected packet from peer");
                return Err(IgnoreReason::InvalidPacketTime);
            }
        };

        #[cfg(feature = "ntpv5")]
        if message.valid_server_response(request_identifier, self.nts.is_some()) {
            if let ProtocolVersion::V4UpgradingToV5 { tries_left } = self.protocol_version {
                let tries_left = tries_left.saturating_sub(1);
                if message.is_upgrade() {
                    info!("Received a valid upgrade response, switching to NTPv5!");
                    self.protocol_version = ProtocolVersion::V5;
                } else if tries_left == 0 {
                    info!("Server does not support NTPv5, stopping the upgrade process");
                    self.protocol_version = ProtocolVersion::V4;
                } else {
                    debug!(tries_left, "Server did not yet responde with upgrade code");
                    self.protocol_version = ProtocolVersion::V4UpgradingToV5 { tries_left };
                };
            }
        }

        if !message.valid_server_response(request_identifier, self.nts.is_some()) {
            // Packets should be a response to a previous request from us,
            // if not just ignore. Note that this might also happen when
            // we reset between sending the request and receiving the response.
            // We do this as the first check since accepting even a KISS
            // packet that is not a response will leave us vulnerable
            // to denial of service attacks.
            debug!("Received old/unexpected packet from peer");
            Err(IgnoreReason::InvalidPacketTime)
        } else if message.is_kiss_rate() {
            // KISS packets may not have correct timestamps at all, handle them anyway
            self.remote_min_poll_interval = Ord::max(
                self.remote_min_poll_interval
                    .inc(self.peer_defaults_config.poll_interval_limits),
                self.last_poll_interval,
            );
            warn!(?self.remote_min_poll_interval, "Peer requested rate limit");
            Err(IgnoreReason::KissIgnore)
        } else if message.is_kiss_rstr() || message.is_kiss_deny() {
            warn!("Peer denied service");
            // KISS packets may not have correct timestamps at all, handle them anyway
            Err(IgnoreReason::KissDemobilize)
        } else if message.is_kiss_ntsn() {
            warn!("Received nts not-acknowledge");
            // as these can be easily faked, we dont immediately give up on receiving
            // a response, however, for the purpose of backoff we do count it as a response.
            // This ensures that if we have expired cookies, we get through them
            // fairly quickly.
            self.backoff_interval = self.peer_defaults_config.poll_interval_limits.min;
            Err(IgnoreReason::KissNtsNack)
        } else if message.is_kiss() {
            warn!("Unrecognized KISS Message from peer");
            // Ignore unrecognized control messages
            Err(IgnoreReason::KissIgnore)
        } else if message.stratum() > MAX_STRATUM {
            // A servers stratum should be between 1 and MAX_STRATUM (16) inclusive.
            warn!(
                "Received message from server with excessive stratum {}",
                message.stratum()
            );
            Err(IgnoreReason::InvalidStratum)
        } else if message.mode() != NtpAssociationMode::Server {
            // we currently only support a client <-> server association
            warn!("Received packet with invalid mode");
            Err(IgnoreReason::InvalidMode)
        } else {
            Ok(self.process_message(system, message, local_clock_time, send_time, recv_time))
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_message(
        &mut self,
        system: SystemSnapshot,
        message: NtpPacket,
        local_clock_time: NtpInstant,
        send_time: NtpTimestamp,
        recv_time: NtpTimestamp,
    ) -> Update {
        trace!("Packet accepted for processing");
        // For reachability, mark that we have had a response
        self.reach.received_packet();

        // Got a response, so no need for unreachability backoff
        self.backoff_interval = self.peer_defaults_config.poll_interval_limits.min;

        // we received this packet, and don't want to accept future ones with this next_expected_origin
        self.current_request_identifier = None;

        // Update stratum and reference id
        self.stratum = message.stratum();
        self.reference_id = message.reference_id();

        #[cfg(feature = "ntpv5")]
        if let NtpHeader::V5(header) = message.header() {
            // Handle new requested poll interval
            let requested_poll = message.poll();
            if requested_poll > self.remote_min_poll_interval {
                debug!(
                    ?requested_poll,
                    ?self.remote_min_poll_interval,
                    "Adapting to longer poll interval requested by server"
                );
                self.remote_min_poll_interval = requested_poll;
            }

            // Update our bloom filter
            if let Some(filter) = &mut self.bloom_filter {
                let bloom_responses =
                    message
                        .untrusted_extension_fields()
                        .filter_map(|ef| match ef {
                            ExtensionField::ReferenceIdResponse(response) => Some(response),
                            _ => None,
                        });

                for ref_id in bloom_responses {
                    let result = filter.handle_response(header.client_cookie, ref_id);
                    if let Err(err) = result {
                        info!(?err, "Invalid ReferenceIdResponse from peer, ignoring...")
                    }
                }
            }
        }

        // generate a measurement
        let measurement = Measurement::from_packet(
            &message,
            send_time,
            recv_time,
            local_clock_time,
            system.time_snapshot.precision,
        );

        // Process new cookies
        if let Some(nts) = self.nts.as_mut() {
            for cookie in message.new_cookies() {
                nts.cookies.store(cookie);
            }
        }

        Update::NewMeasurement(PeerSnapshot::from_peer(self), measurement)
    }

    #[instrument(level="trace", skip(self), fields(peer = debug(self.source_id)))]
    pub fn reset(&mut self) {
        // make sure in-flight messages are ignored
        self.current_request_identifier = None;

        info!(our_id = ?self.our_id, source_id = ?self.source_id, "Source reset");
    }

    #[cfg(test)]
    pub(crate) fn test_peer() -> Self {
        use std::net::{IpAddr, Ipv4Addr};

        Peer {
            nts: None,

            last_poll_interval: PollInterval::default(),
            backoff_interval: PollInterval::default(),
            remote_min_poll_interval: PollInterval::default(),

            current_request_identifier: None,

            source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            source_id: ReferenceId::from_int(0),
            our_id: ReferenceId::from_int(0),
            reach: Reach::default(),
            tries: 0,

            stratum: 0,
            reference_id: ReferenceId::from_int(0),

            peer_defaults_config: SourceDefaultsConfig::default(),

            protocol_version: Default::default(),

            #[cfg(feature = "ntpv5")]
            bloom_filter: Some(RemoteBloomFilter::new(16).unwrap()),
        }
    }
}

#[cfg(feature = "__internal-fuzz")]
pub fn fuzz_measurement_from_packet(
    client: u64,
    client_interval: u32,
    server: u64,
    server_interval: u32,
    client_precision: i8,
    server_precision: i8,
) {
    let mut packet = NtpPacket::test();
    packet.set_origin_timestamp(NtpTimestamp::from_fixed_int(client));
    packet.set_receive_timestamp(NtpTimestamp::from_fixed_int(server));
    packet.set_transmit_timestamp(NtpTimestamp::from_fixed_int(
        server.wrapping_add(server_interval as u64),
    ));
    packet.set_precision(server_precision);

    let result = Measurement::from_packet(
        &packet,
        NtpTimestamp::from_fixed_int(client),
        NtpTimestamp::from_fixed_int(client.wrapping_add(client_interval as u64)),
        NtpInstant::now(),
        NtpDuration::from_exponent(client_precision),
    );

    assert!(result.delay >= NtpDuration::ZERO);
}

#[cfg(test)]
mod test {
    use crate::{packet::NoCipher, time_types::PollIntervalLimits, NtpClock};

    use super::*;
    #[cfg(feature = "ntpv5")]
    use crate::packet::v5::server_reference_id::{BloomFilter, ServerId};
    #[cfg(feature = "ntpv5")]
    use rand::thread_rng;
    use std::time::Duration;

    #[derive(Debug, Clone, Default)]
    struct TestClock {}
    const EPOCH_OFFSET: u32 = (70 * 365 + 17) * 86400;
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

    #[test]
    fn test_measurement_from_packet() {
        let instant = NtpInstant::now();

        let mut packet = NtpPacket::test();
        packet.set_receive_timestamp(NtpTimestamp::from_fixed_int(1));
        packet.set_transmit_timestamp(NtpTimestamp::from_fixed_int(2));
        let result = Measurement::from_packet(
            &packet,
            NtpTimestamp::from_fixed_int(0),
            NtpTimestamp::from_fixed_int(3),
            instant,
            NtpDuration::from_exponent(-32),
        );
        assert_eq!(result.offset, NtpDuration::from_fixed_int(0));
        assert_eq!(result.delay, NtpDuration::from_fixed_int(2));

        packet.set_receive_timestamp(NtpTimestamp::from_fixed_int(2));
        packet.set_transmit_timestamp(NtpTimestamp::from_fixed_int(3));
        let result = Measurement::from_packet(
            &packet,
            NtpTimestamp::from_fixed_int(0),
            NtpTimestamp::from_fixed_int(3),
            instant,
            NtpDuration::from_exponent(-32),
        );
        assert_eq!(result.offset, NtpDuration::from_fixed_int(1));
        assert_eq!(result.delay, NtpDuration::from_fixed_int(2));

        packet.set_receive_timestamp(NtpTimestamp::from_fixed_int(0));
        packet.set_transmit_timestamp(NtpTimestamp::from_fixed_int(5));
        let result = Measurement::from_packet(
            &packet,
            NtpTimestamp::from_fixed_int(0),
            NtpTimestamp::from_fixed_int(3),
            instant,
            NtpDuration::from_exponent(-32),
        );
        assert_eq!(result.offset, NtpDuration::from_fixed_int(1));
        assert_eq!(result.delay, NtpDuration::from_fixed_int(1));
    }

    #[test]
    fn reachability() {
        let mut reach = Reach::default();

        // the default reach register value is 0, and hence not reachable
        assert!(!reach.is_reachable());

        // when we receive a packet, we set the right-most bit;
        // we just received a packet from the peer, so it is reachable
        reach.received_packet();
        assert!(reach.is_reachable());

        // on every poll, the register is shifted to the left, and there are
        // 8 bits. So we can poll 7 times and the peer is still considered reachable
        for _ in 0..7 {
            reach.poll();
        }

        assert!(reach.is_reachable());

        // but one more poll and all 1 bits have been shifted out;
        // the peer is no longer reachable
        reach.poll();
        assert!(!reach.is_reachable());

        // until we receive a packet from it again
        reach.received_packet();
        assert!(reach.is_reachable());
    }

    #[test]
    fn test_accept_synchronization() {
        use AcceptSynchronizationError::*;

        let mut peer = Peer::test_peer();

        #[cfg(feature = "ntpv5")]
        let server_id = ServerId::new(&mut rand::thread_rng());

        macro_rules! accept {
            () => {{
                let snapshot = PeerSnapshot::from_peer(&peer);
                snapshot.accept_synchronization(
                    16,
                    #[cfg(feature = "ntpv5")]
                    &server_id,
                )
            }};
        }

        // by default, the packet id and the peer's id are the same, indicating a loop
        assert_eq!(accept!(), Err(Loop));

        peer.our_id = ReferenceId::from_int(42);

        assert_eq!(accept!(), Err(ServerUnreachable));

        peer.reach.received_packet();

        assert_eq!(accept!(), Ok(()));

        peer.stratum = 42;
        assert_eq!(accept!(), Err(Stratum));
    }

    #[test]
    fn test_poll_interval() {
        let base = NtpInstant::now();
        let mut peer = Peer::test_peer();
        let mut system = SystemSnapshot::default();

        assert!(peer.current_poll_interval(system) >= peer.remote_min_poll_interval);
        assert!(peer.current_poll_interval(system) >= system.time_snapshot.poll_interval);

        system.time_snapshot.poll_interval = PollIntervalLimits::default().max;

        assert!(peer.current_poll_interval(system) >= peer.remote_min_poll_interval);
        assert!(peer.current_poll_interval(system) >= system.time_snapshot.poll_interval);

        system.time_snapshot.poll_interval = PollIntervalLimits::default().min;
        peer.remote_min_poll_interval = PollIntervalLimits::default().max;

        assert!(peer.current_poll_interval(system) >= peer.remote_min_poll_interval);
        assert!(peer.current_poll_interval(system) >= system.time_snapshot.poll_interval);

        peer.remote_min_poll_interval = PollIntervalLimits::default().min;

        let prev = peer.current_poll_interval(system);
        let mut buf = [0; 1024];
        let packetbuf = peer
            .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
            .unwrap();
        let packet = NtpPacket::deserialize(packetbuf, &NoCipher).unwrap().0;
        assert!(peer.current_poll_interval(system) > prev);
        let mut response = NtpPacket::test();
        response.set_mode(NtpAssociationMode::Server);
        response.set_stratum(1);
        response.set_origin_timestamp(packet.transmit_timestamp());
        assert!(peer
            .handle_incoming(
                system,
                &response.serialize_without_encryption_vec(None).unwrap(),
                base,
                NtpTimestamp::default(),
                NtpTimestamp::default()
            )
            .is_ok());
        assert_eq!(peer.current_poll_interval(system), prev);

        let prev = peer.current_poll_interval(system);
        let mut buf = [0; 1024];
        let packetbuf = peer
            .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
            .unwrap();
        let packet = NtpPacket::deserialize(packetbuf, &NoCipher).unwrap().0;
        assert!(peer.current_poll_interval(system) > prev);
        let mut response = NtpPacket::test();
        response.set_mode(NtpAssociationMode::Server);
        response.set_stratum(0);
        response.set_origin_timestamp(packet.transmit_timestamp());
        response.set_reference_id(ReferenceId::KISS_RATE);
        assert!(peer
            .handle_incoming(
                system,
                &response.serialize_without_encryption_vec(None).unwrap(),
                base,
                NtpTimestamp::default(),
                NtpTimestamp::default()
            )
            .is_err());
        assert!(peer.current_poll_interval(system) > prev);
        assert!(peer.remote_min_poll_interval > prev);
    }

    #[test]
    fn test_handle_incoming() {
        let base = NtpInstant::now();
        let mut peer = Peer::test_peer();

        let system = SystemSnapshot::default();
        let mut buf = [0; 1024];
        let outgoingbuf = peer
            .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
            .unwrap();
        let outgoing = NtpPacket::deserialize(outgoingbuf, &NoCipher).unwrap().0;
        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        packet.set_stratum(1);
        packet.set_mode(NtpAssociationMode::Server);
        packet.set_origin_timestamp(outgoing.transmit_timestamp());
        packet.set_receive_timestamp(NtpTimestamp::from_fixed_int(100));
        packet.set_transmit_timestamp(NtpTimestamp::from_fixed_int(200));

        assert!(peer
            .handle_incoming(
                system,
                &packet.serialize_without_encryption_vec(None).unwrap(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(400)
            )
            .is_ok());
        //assert_eq!(peer.timestate.last_packet, packet);
        assert!(peer
            .handle_incoming(
                system,
                &packet.serialize_without_encryption_vec(None).unwrap(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(500)
            )
            .is_err());
    }

    #[test]
    fn test_startup_unreachable() {
        let mut peer = Peer::test_peer();
        let system = SystemSnapshot::default();
        let mut buf = [0; 1024];
        assert!(peer
            .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
            .is_ok());
        assert!(peer
            .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
            .is_ok());
        assert!(peer
            .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
            .is_ok());
        assert!(matches!(
            peer.generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default()),
            Err(PollError::PeerUnreachable)
        ));
    }

    #[test]
    fn test_running_unreachable() {
        let base = NtpInstant::now();
        let mut peer = Peer::test_peer();

        let system = SystemSnapshot::default();
        let mut buf = [0; 1024];
        let outgoingbuf = peer
            .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
            .unwrap();
        let outgoing = NtpPacket::deserialize(outgoingbuf, &NoCipher).unwrap().0;
        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        packet.set_stratum(1);
        packet.set_mode(NtpAssociationMode::Server);
        packet.set_origin_timestamp(outgoing.transmit_timestamp());
        packet.set_receive_timestamp(NtpTimestamp::from_fixed_int(100));
        packet.set_transmit_timestamp(NtpTimestamp::from_fixed_int(200));
        assert!(peer
            .handle_incoming(
                system,
                &packet.serialize_without_encryption_vec(None).unwrap(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(400)
            )
            .is_ok());

        assert!(peer
            .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
            .is_ok());
        assert!(peer
            .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
            .is_ok());
        assert!(peer
            .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
            .is_ok());
        assert!(peer
            .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
            .is_ok());
        assert!(peer
            .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
            .is_ok());
        assert!(peer
            .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
            .is_ok());
        assert!(peer
            .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
            .is_ok());
        assert!(peer
            .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
            .is_ok());
        assert!(matches!(
            peer.generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default()),
            Err(PollError::PeerUnreachable)
        ));
    }

    #[test]
    fn test_stratum_checks() {
        let base = NtpInstant::now();
        let mut peer = Peer::test_peer();

        let system = SystemSnapshot::default();
        let mut buf = [0; 1024];
        let outgoingbuf = peer
            .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
            .unwrap();
        let outgoing = NtpPacket::deserialize(outgoingbuf, &NoCipher).unwrap().0;
        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        packet.set_stratum(MAX_STRATUM + 1);
        packet.set_mode(NtpAssociationMode::Server);
        packet.set_origin_timestamp(outgoing.transmit_timestamp());
        packet.set_receive_timestamp(NtpTimestamp::from_fixed_int(100));
        packet.set_transmit_timestamp(NtpTimestamp::from_fixed_int(200));
        assert!(peer
            .handle_incoming(
                system,
                &packet.serialize_without_encryption_vec(None).unwrap(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(500)
            )
            .is_err());

        packet.set_stratum(0);
        assert!(peer
            .handle_incoming(
                system,
                &packet.serialize_without_encryption_vec(None).unwrap(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(500)
            )
            .is_err());
    }

    #[test]
    fn test_handle_kod() {
        let base = NtpInstant::now();
        let mut peer = Peer::test_peer();

        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        packet.set_reference_id(ReferenceId::KISS_RSTR);
        packet.set_mode(NtpAssociationMode::Server);
        assert!(!matches!(
            peer.handle_incoming(
                system,
                &packet.serialize_without_encryption_vec(None).unwrap(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(100)
            ),
            Err(IgnoreReason::KissDemobilize)
        ));

        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        let mut buf = [0; 1024];
        let outgoingbuf = peer
            .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
            .unwrap();
        let outgoing = NtpPacket::deserialize(outgoingbuf, &NoCipher).unwrap().0;
        packet.set_reference_id(ReferenceId::KISS_RSTR);
        packet.set_origin_timestamp(outgoing.transmit_timestamp());
        packet.set_mode(NtpAssociationMode::Server);
        assert!(matches!(
            peer.handle_incoming(
                system,
                &packet.serialize_without_encryption_vec(None).unwrap(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(100)
            ),
            Err(IgnoreReason::KissDemobilize)
        ));

        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        packet.set_reference_id(ReferenceId::KISS_DENY);
        packet.set_mode(NtpAssociationMode::Server);
        assert!(!matches!(
            peer.handle_incoming(
                system,
                &packet.serialize_without_encryption_vec(None).unwrap(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(100)
            ),
            Err(IgnoreReason::KissDemobilize)
        ));

        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        let outgoingbuf = peer
            .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
            .unwrap();
        let outgoing = NtpPacket::deserialize(outgoingbuf, &NoCipher).unwrap().0;
        packet.set_reference_id(ReferenceId::KISS_DENY);
        packet.set_origin_timestamp(outgoing.transmit_timestamp());
        packet.set_mode(NtpAssociationMode::Server);
        assert!(matches!(
            peer.handle_incoming(
                system,
                &packet.serialize_without_encryption_vec(None).unwrap(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(100)
            ),
            Err(IgnoreReason::KissDemobilize)
        ));

        let old_remote_interval = peer.remote_min_poll_interval;
        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        packet.set_reference_id(ReferenceId::KISS_RATE);
        packet.set_mode(NtpAssociationMode::Server);
        assert!(peer
            .handle_incoming(
                system,
                &packet.serialize_without_encryption_vec(None).unwrap(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(100)
            )
            .is_err());
        assert_eq!(peer.remote_min_poll_interval, old_remote_interval);

        let old_remote_interval = peer.remote_min_poll_interval;
        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        let mut buf = [0; 1024];
        let outgoingbuf = peer
            .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
            .unwrap();
        let outgoing = NtpPacket::deserialize(outgoingbuf, &NoCipher).unwrap().0;
        packet.set_reference_id(ReferenceId::KISS_RATE);
        packet.set_origin_timestamp(outgoing.transmit_timestamp());
        packet.set_mode(NtpAssociationMode::Server);
        assert!(peer
            .handle_incoming(
                system,
                &packet.serialize_without_encryption_vec(None).unwrap(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(100)
            )
            .is_err());
        assert!(peer.remote_min_poll_interval >= old_remote_interval);
    }

    #[cfg(feature = "ntpv5")]
    #[test]
    fn upgrade_state_machine_does_stop() {
        let mut peer = Peer::test_peer();
        let mut buf = [0; 1024];
        let system = SystemSnapshot::default();
        let peer_defaults_config = SourceDefaultsConfig::default();
        let clock = TestClock {};

        assert!(matches!(
            peer.protocol_version,
            ProtocolVersion::V4UpgradingToV5 { .. }
        ));

        for _ in 0..8 {
            let poll = peer
                .generate_poll_message(&mut buf, system, &peer_defaults_config)
                .unwrap();

            let poll_len: usize = poll.len();
            let (poll, _) = NtpPacket::deserialize(poll, &NoCipher).unwrap();
            assert_eq!(poll.version(), 4);
            assert!(poll.is_upgrade());

            let response =
                NtpPacket::timestamp_response(&system, poll, NtpTimestamp::default(), &clock);
            let mut response = response
                .serialize_without_encryption_vec(Some(poll_len))
                .unwrap();

            // Kill the reference timestamp
            response[16] = 0;

            peer.handle_incoming(
                system,
                &response,
                NtpInstant::now(),
                NtpTimestamp::default(),
                NtpTimestamp::default(),
            )
            .unwrap();
        }

        let poll = peer
            .generate_poll_message(&mut buf, system, &peer_defaults_config)
            .unwrap();
        let (poll, _) = NtpPacket::deserialize(poll, &NoCipher).unwrap();
        assert_eq!(poll.version(), 4);
        assert!(!poll.is_upgrade());
    }

    #[cfg(feature = "ntpv5")]
    #[test]
    fn upgrade_state_machine_does_upgrade() {
        let mut peer = Peer::test_peer();
        let mut buf = [0; 1024];
        let system = SystemSnapshot::default();
        let peer_defaults_config = SourceDefaultsConfig::default();
        let clock = TestClock {};

        assert!(matches!(
            peer.protocol_version,
            ProtocolVersion::V4UpgradingToV5 { .. }
        ));

        let poll = peer
            .generate_poll_message(&mut buf, system, &peer_defaults_config)
            .unwrap();

        let poll_len = poll.len();
        let (poll, _) = NtpPacket::deserialize(poll, &NoCipher).unwrap();
        assert_eq!(poll.version(), 4);
        assert!(poll.is_upgrade());

        let response =
            NtpPacket::timestamp_response(&system, poll, NtpTimestamp::default(), &clock);
        let response = response
            .serialize_without_encryption_vec(Some(poll_len))
            .unwrap();

        peer.handle_incoming(
            system,
            &response,
            NtpInstant::now(),
            NtpTimestamp::default(),
            NtpTimestamp::default(),
        )
        .unwrap();

        // We should have received a upgrade response and updated to NTPv5
        assert!(matches!(peer.protocol_version, ProtocolVersion::V5));

        let poll = peer
            .generate_poll_message(&mut buf, system, &peer_defaults_config)
            .unwrap();
        let (poll, _) = NtpPacket::deserialize(poll, &NoCipher).unwrap();
        assert_eq!(poll.version(), 5);
    }

    #[cfg(feature = "ntpv5")]
    #[test]
    fn bloom_filters_will_synchronize_at_some_point() {
        let mut server_filter = BloomFilter::new();
        server_filter.add_id(&ServerId::new(&mut thread_rng()));

        let mut client = Peer::test_peer();
        client.protocol_version = ProtocolVersion::V5;

        let clock = TestClock::default();
        let system = SystemSnapshot::default();

        let mut server_system = SystemSnapshot::default();
        server_system.bloom_filter = server_filter.clone();

        let mut tries = 0;

        while client
            .bloom_filter
            .as_ref()
            .unwrap()
            .full_filter()
            .is_none()
            && tries < 100
        {
            let mut buf = [0; 1024];
            let req = client
                .generate_poll_message(&mut buf, system, &SourceDefaultsConfig::default())
                .unwrap();

            let (req, _) = NtpPacket::deserialize(req, &NoCipher).unwrap();
            let response =
                NtpPacket::timestamp_response(&server_system, req, NtpTimestamp::default(), &clock);
            let resp_bytes = response.serialize_without_encryption_vec().unwrap();

            client
                .handle_incoming(
                    system,
                    &resp_bytes,
                    NtpInstant::now(),
                    NtpTimestamp::default(),
                    NtpTimestamp::default(),
                )
                .unwrap();

            tries += 1;
        }

        assert_eq!(
            Some(&server_filter),
            client.bloom_filter.unwrap().full_filter()
        );
    }
}
