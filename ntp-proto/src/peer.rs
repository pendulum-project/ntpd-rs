use std::io::Cursor;

use crate::{
    config::PeerDefaultsConfig,
    cookiestash::CookieStash,
    identifiers::ReferenceId,
    packet::{Cipher, NtpAssociationMode, NtpLeapIndicator, NtpPacket, RequestIdentifier},
    system::SystemSnapshot,
    time_types::{NtpDuration, NtpInstant, NtpTimestamp, PollInterval},
};
use serde::{Deserialize, Serialize};
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

    peer_id: ReferenceId,
    our_id: ReferenceId,
    reach: Reach,
    tries: usize,

    peer_defaults_config: PeerDefaultsConfig,
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

    /// Number of polls remaining until unreachable
    pub fn reachability_score(&self) -> u32 {
        8 - self.0.trailing_zeros()
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
    pub peer_id: ReferenceId,
    pub our_id: ReferenceId,

    pub poll_interval: PollInterval,
    pub reach: Reach,

    pub stratum: u8,
    pub reference_id: ReferenceId,
}

impl PeerSnapshot {
    pub fn accept_synchronization(
        &self,
        local_stratum: u8,
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
            info!("Peer rejected because of detected synchornization loop");
            return Err(Loop);
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
            peer_id: peer.peer_id,
            our_id: peer.our_id,
            stratum: peer.stratum,
            reference_id: peer.reference_id,
            reach: peer.reach,
            poll_interval: peer.last_poll_interval,
        }
    }
}

#[cfg(feature = "__internal-test")]
pub fn peer_snapshot() -> PeerSnapshot {
    let mut reach = crate::peer::Reach::default();
    reach.received_packet();

    PeerSnapshot {
        peer_id: ReferenceId::from_int(0),
        stratum: 0,
        reference_id: ReferenceId::from_int(0),

        our_id: ReferenceId::from_int(1),
        reach,
        poll_interval: crate::time_types::PollIntervalLimits::default().min,
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

impl Peer {
    #[instrument]
    pub fn new(
        our_id: ReferenceId,
        peer_id: ReferenceId,
        local_clock_time: NtpInstant,
        peer_defaults_config: PeerDefaultsConfig,
    ) -> Self {
        Self {
            nts: None,

            last_poll_interval: peer_defaults_config.poll_interval_limits.min,
            backoff_interval: peer_defaults_config.poll_interval_limits.min,
            remote_min_poll_interval: peer_defaults_config.poll_interval_limits.min,

            current_request_identifier: None,
            our_id,
            peer_id,
            reach: Default::default(),
            tries: 0,

            stratum: 16,
            reference_id: ReferenceId::NONE,

            peer_defaults_config,
        }
    }

    #[instrument]
    pub fn new_nts(
        our_id: ReferenceId,
        peer_id: ReferenceId,
        local_clock_time: NtpInstant,
        peer_defaults_config: PeerDefaultsConfig,
        nts: Box<PeerNtsData>,
    ) -> Self {
        Self {
            nts: Some(nts),
            ..Self::new(our_id, peer_id, local_clock_time, peer_defaults_config)
        }
    }

    pub fn update_config(&mut self, peer_defaults_config: PeerDefaultsConfig) {
        self.peer_defaults_config = peer_defaults_config;
    }

    pub fn current_poll_interval(&self, system: SystemSnapshot) -> PollInterval {
        system
            .time_snapshot
            .poll_interval
            .max(self.backoff_interval)
            .max(self.remote_min_poll_interval)
    }

    pub fn generate_poll_message<'a>(
        &mut self,
        buf: &'a mut [u8],
        system: SystemSnapshot,
        peer_defaults_config: &PeerDefaultsConfig,
    ) -> Result<&'a [u8], PollError> {
        if !self.reach.is_reachable() && self.tries >= STARTUP_TRIES_THRESHOLD {
            return Err(PollError::PeerUnreachable);
        }

        self.reach.poll();
        self.tries = self.tries.saturating_add(1);

        let poll_interval = self.current_poll_interval(system);
        let (packet, identifier) = match &mut self.nts {
            Some(nts) => {
                let cookie = nts.cookies.get().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::Other, NtsError::OutOfCookies)
                })?;
                NtpPacket::nts_poll_message(&cookie, nts.cookies.gap(), poll_interval)
            }
            None => NtpPacket::poll_message(poll_interval),
        };
        self.current_request_identifier = Some((identifier, NtpInstant::now() + POLL_WINDOW));

        // Ensure we don't spam the remote with polls if it is not reachable
        self.backoff_interval = poll_interval.inc(peer_defaults_config.poll_interval_limits);

        // Write packet to buffer
        let mut cursor = Cursor::new(buf);
        packet.serialize(&mut cursor, &self.nts.as_ref().map(|nts| nts.c2s.as_ref()))?;
        let used = cursor.position();
        let result = &cursor.into_inner()[..used as usize];

        Ok(result)
    }

    #[instrument(skip(self, system), fields(peer = debug(self.peer_id)))]
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

        let request_identifier = match self.current_request_identifier {
            Some((next_expected_origin, validity)) if validity >= NtpInstant::now() => {
                next_expected_origin
            }
            _ => {
                debug!("Received old/unexpected packet from peer");
                return Err(IgnoreReason::InvalidPacketTime);
            }
        };

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

    #[instrument(level="trace", skip(self), fields(peer = debug(self.peer_id)))]
    pub fn reset(&mut self) {
        // make sure in-flight messages are ignored
        self.current_request_identifier = None;

        info!(our_id = ?self.our_id, peer_id = ?self.peer_id, "Peer reset");
    }

    #[cfg(test)]
    pub(crate) fn test_peer() -> Self {
        Peer {
            nts: None,

            last_poll_interval: PollInterval::default(),
            backoff_interval: PollInterval::default(),
            remote_min_poll_interval: PollInterval::default(),

            current_request_identifier: None,

            peer_id: ReferenceId::from_int(0),
            our_id: ReferenceId::from_int(0),
            reach: Reach::default(),
            tries: 0,

            stratum: 0,
            reference_id: ReferenceId::from_int(0),

            peer_defaults_config: PeerDefaultsConfig::default(),
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
    use crate::{packet::NoCipher, time_types::PollIntervalLimits};

    use super::*;
    use std::time::Duration;

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

        macro_rules! accept {
            () => {{
                let snapshot = PeerSnapshot::from_peer(&peer);
                snapshot.accept_synchronization(16)
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
            .generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default())
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
                &response.serialize_without_encryption_vec().unwrap(),
                base,
                NtpTimestamp::default(),
                NtpTimestamp::default()
            )
            .is_ok());
        assert_eq!(peer.current_poll_interval(system), prev);

        let prev = peer.current_poll_interval(system);
        let mut buf = [0; 1024];
        let packetbuf = peer
            .generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default())
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
                &response.serialize_without_encryption_vec().unwrap(),
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
            .generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default())
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
                &packet.serialize_without_encryption_vec().unwrap(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(400)
            )
            .is_ok());
        //assert_eq!(peer.timestate.last_packet, packet);
        assert!(peer
            .handle_incoming(
                system,
                &packet.serialize_without_encryption_vec().unwrap(),
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
            .generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default())
            .is_ok());
        assert!(peer
            .generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default())
            .is_ok());
        assert!(peer
            .generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default())
            .is_ok());
        assert!(matches!(
            peer.generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default()),
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
            .generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default())
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
                &packet.serialize_without_encryption_vec().unwrap(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(400)
            )
            .is_ok());

        assert!(peer
            .generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default())
            .is_ok());
        assert!(peer
            .generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default())
            .is_ok());
        assert!(peer
            .generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default())
            .is_ok());
        assert!(peer
            .generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default())
            .is_ok());
        assert!(peer
            .generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default())
            .is_ok());
        assert!(peer
            .generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default())
            .is_ok());
        assert!(peer
            .generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default())
            .is_ok());
        assert!(peer
            .generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default())
            .is_ok());
        assert!(matches!(
            peer.generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default()),
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
            .generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default())
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
                &packet.serialize_without_encryption_vec().unwrap(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(500)
            )
            .is_err());

        packet.set_stratum(0);
        assert!(peer
            .handle_incoming(
                system,
                &packet.serialize_without_encryption_vec().unwrap(),
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
                &packet.serialize_without_encryption_vec().unwrap(),
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
            .generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default())
            .unwrap();
        let outgoing = NtpPacket::deserialize(outgoingbuf, &NoCipher).unwrap().0;
        packet.set_reference_id(ReferenceId::KISS_RSTR);
        packet.set_origin_timestamp(outgoing.transmit_timestamp());
        packet.set_mode(NtpAssociationMode::Server);
        assert!(matches!(
            peer.handle_incoming(
                system,
                &packet.serialize_without_encryption_vec().unwrap(),
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
                &packet.serialize_without_encryption_vec().unwrap(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(100)
            ),
            Err(IgnoreReason::KissDemobilize)
        ));

        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        let outgoingbuf = peer
            .generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default())
            .unwrap();
        let outgoing = NtpPacket::deserialize(outgoingbuf, &NoCipher).unwrap().0;
        packet.set_reference_id(ReferenceId::KISS_DENY);
        packet.set_origin_timestamp(outgoing.transmit_timestamp());
        packet.set_mode(NtpAssociationMode::Server);
        assert!(matches!(
            peer.handle_incoming(
                system,
                &packet.serialize_without_encryption_vec().unwrap(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(100)
            ),
            Err(IgnoreReason::KissDemobilize)
        ));

        let old_poll_interval = peer.last_poll_interval;
        let old_remote_interval = peer.remote_min_poll_interval;
        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        packet.set_reference_id(ReferenceId::KISS_RATE);
        packet.set_mode(NtpAssociationMode::Server);
        assert!(peer
            .handle_incoming(
                system,
                &packet.serialize_without_encryption_vec().unwrap(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(100)
            )
            .is_err());
        assert_eq!(peer.remote_min_poll_interval, old_poll_interval);
        assert_eq!(peer.remote_min_poll_interval, old_remote_interval);

        let old_poll_interval = peer.last_poll_interval;
        let old_remote_interval = peer.remote_min_poll_interval;
        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        let mut buf = [0; 1024];
        let outgoingbuf = peer
            .generate_poll_message(&mut buf, system, &PeerDefaultsConfig::default())
            .unwrap();
        let outgoing = NtpPacket::deserialize(outgoingbuf, &NoCipher).unwrap().0;
        packet.set_reference_id(ReferenceId::KISS_RATE);
        packet.set_origin_timestamp(outgoing.transmit_timestamp());
        packet.set_mode(NtpAssociationMode::Server);
        assert!(peer
            .handle_incoming(
                system,
                &packet.serialize_without_encryption_vec().unwrap(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(100)
            )
            .is_err());
        assert!(peer.remote_min_poll_interval > old_poll_interval);
        assert!(peer.remote_min_poll_interval >= old_remote_interval);
    }
}
