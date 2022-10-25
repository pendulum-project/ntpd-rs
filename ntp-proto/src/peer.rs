use crate::{
    filter::{FilterTuple, LastMeasurements},
    packet::{NtpAssociationMode, NtpLeapIndicator, RequestIdentifier},
    time_types::{FrequencyTolerance, NtpInstant},
    NtpDuration, NtpPacket, NtpTimestamp, PollInterval, ReferenceId, SystemConfig,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, trace, warn};

const MAX_STRATUM: u8 = 16;
const POLL_WINDOW: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct PeerStatistics {
    pub offset: NtpDuration,
    pub delay: NtpDuration,

    pub dispersion: NtpDuration,
    pub jitter: f64,
}

#[derive(Debug, Clone)]
pub struct Peer {
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

    peer_id: ReferenceId,
    our_id: ReferenceId,
    reach: Reach,

    timestate: PeerTimeState,
}

#[derive(Debug, Copy, Clone)]
pub struct Measurement {
    pub delay: NtpDuration,
    pub offset: NtpDuration,
    pub localtime: NtpTimestamp,
    pub monotime: NtpInstant,
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
            localtime: send_timestamp + (recv_timestamp - send_timestamp) / 2,
            monotime: local_clock_time,
        }
    }
}

#[derive(Debug, Clone)]
struct PeerTimeState {
    statistics: PeerStatistics,
    last_measurements: LastMeasurements,
    last_packet: NtpPacket<'static>,
    time: NtpInstant,
}

impl PeerTimeState {
    fn update(
        &mut self,
        measurement: Measurement,
        packet: NtpPacket,
        system: SystemSnapshot,
        system_config: &SystemConfig,
    ) -> Option<()> {
        let filter_input = FilterTuple::from_measurement(
            measurement,
            &packet,
            system.precision,
            system_config.frequency_tolerance,
        );

        self.last_packet = packet.into_owned();

        let updated = self.last_measurements.step(
            filter_input,
            self.time,
            system.leap_indicator,
            system.precision,
            system_config.frequency_tolerance,
        );

        if let Some((statistics, time)) = updated {
            self.statistics = statistics;
            self.time = time;

            Some(())
        } else {
            None
        }
    }

    /// Root distance without the `(local_clock_time - self.time) * PHI` term
    fn root_distance_without_time(&self) -> NtpDuration {
        NtpDuration::MIN_DISPERSION.max(self.last_packet.root_delay() + self.statistics.delay)
            / 2i64
            + self.last_packet.root_dispersion()
            + self.statistics.dispersion
            + NtpDuration::from_seconds(self.statistics.jitter)
    }

    /// The root synchronization distance is the maximum error due to
    /// all causes of the local clock relative to the primary server.
    /// It is defined as half the total delay plus total dispersion
    /// plus peer jitter.
    #[cfg(test)]
    fn root_distance(
        &self,
        local_clock_time: NtpInstant,
        frequency_tolerance: FrequencyTolerance,
    ) -> NtpDuration {
        self.root_distance_without_time()
            + NtpInstant::abs_diff(local_clock_time, self.time) * frequency_tolerance
    }

    /// reset just the measurement data, the poll and connection data is unchanged
    pub fn reset_measurements(&mut self) {
        self.statistics = Default::default();
        self.last_measurements = LastMeasurements::new(self.time);
        self.last_packet = Default::default();
    }

    #[cfg(test)]
    pub(crate) fn test_timestate(instant: NtpInstant) -> Self {
        PeerTimeState {
            statistics: Default::default(),
            last_measurements: LastMeasurements::new(instant),
            last_packet: Default::default(),
            time: instant,
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
        self.0 <<= 1
    }

    /// Number of polls since the last message we received
    pub fn unanswered_polls(&self) -> u32 {
        self.0.leading_zeros()
    }

    /// Number of polls remaining until unreachable
    pub fn reachability_score(&self) -> u32 {
        8 - self.0.trailing_zeros()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SystemSnapshot {
    /// Desired poll interval
    pub poll_interval: PollInterval,
    /// Precision of the local clock
    pub precision: NtpDuration,
    /// Log of the precision of the local clock
    pub stratum: u8,
    /// Current root delay
    pub root_delay: NtpDuration,
    /// Current root dispersion
    pub root_dispersion: NtpDuration,
    /// Reference ID of current primary time source
    pub reference_id: ReferenceId,
    /// Current leap indicator state
    pub leap_indicator: NtpLeapIndicator,
    /// Total amount that the clock has stepped
    pub accumulated_steps: NtpDuration,
    /// Crossing this amount of stepping will cause a Panic
    pub accumulated_steps_threshold: Option<NtpDuration>,
}

impl Default for SystemSnapshot {
    fn default() -> Self {
        Self {
            poll_interval: PollInterval::default(),
            precision: NtpDuration::from_exponent(-18),
            stratum: 16,
            root_delay: NtpDuration::ZERO,
            root_dispersion: NtpDuration::ZERO,
            reference_id: ReferenceId::NONE,
            leap_indicator: NtpLeapIndicator::Unknown,
            accumulated_steps: NtpDuration::ZERO,
            accumulated_steps_threshold: None,
        }
    }
}

#[derive(Debug)]
pub enum IgnoreReason {
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
    /// The best packet is older than the peer's current time
    TooOld,
}

#[derive(Debug, Clone, Copy)]
pub struct PeerSnapshot {
    pub root_distance_without_time: NtpDuration,
    pub statistics: PeerStatistics,

    pub time: NtpInstant,
    pub stratum: u8,
    pub peer_id: ReferenceId,
    pub poll_interval: PollInterval,

    pub reference_id: ReferenceId,
    pub our_id: ReferenceId,
    pub reach: Reach,

    pub leap_indicator: NtpLeapIndicator,
    pub root_delay: NtpDuration,
    pub root_dispersion: NtpDuration,
}

impl PeerSnapshot {
    pub fn accept_synchronization(
        &self,
        local_clock_time: NtpInstant,
        frequency_tolerance: FrequencyTolerance,
        distance_threshold: NtpDuration,
        system_poll: PollInterval,
        local_stratum: u8,
    ) -> Result<(), AcceptSynchronizationError> {
        use AcceptSynchronizationError::*;

        let system_poll = system_poll.as_duration();

        // A stratum error occurs if
        //     1: the server has never been synchronized,
        //     2: the server stratum is higher than the local stratum
        if !self.leap_indicator.is_synchronized() || self.stratum >= local_stratum {
            warn!(
                stratum = debug(self.stratum),
                "Peer rejected due to invalid stratum"
            );
            return Err(Stratum);
        }

        //  A distance error occurs if the root distance exceeds the
        //  distance threshold plus an increment equal to one poll interval.
        let distance = self.root_distance(local_clock_time, frequency_tolerance);
        if distance > distance_threshold + (system_poll * frequency_tolerance) {
            debug!(
                ?distance,
                limit = debug(distance_threshold + (system_poll * frequency_tolerance)),
                "Peer rejected due to excessive distance"
            );

            return Err(Distance);
        }

        // Detect whether the remote uses us as their main time reference.
        // if so, we shouldn't sync to them as that would create a loop.
        // Note, this can only ever be an issue if the peer is not using
        // hardware as its source, so ignore reference_id if stratum is 1.
        if self.stratum != 1 && self.reference_id == self.our_id {
            debug!("Peer rejected because of detected synchornization loop");
            return Err(Loop);
        }

        // An unreachable error occurs if the server is unreachable.
        if !self.reach.is_reachable() {
            warn!("Peer unreachable");
            return Err(ServerUnreachable);
        }

        Ok(())
    }

    pub(crate) fn root_distance(
        &self,
        local_clock_time: NtpInstant,
        frequency_tolerance: FrequencyTolerance,
    ) -> NtpDuration {
        self.root_distance_without_time
            + (NtpInstant::abs_diff(local_clock_time, self.time) * frequency_tolerance)
    }

    pub fn from_peer(peer: &Peer) -> Self {
        Self {
            root_distance_without_time: peer.timestate.root_distance_without_time(),
            statistics: peer.timestate.statistics,
            time: peer.timestate.time,
            stratum: peer.timestate.last_packet.stratum(),
            peer_id: peer.peer_id,
            reference_id: peer.timestate.last_packet.reference_id(),
            our_id: peer.our_id,
            reach: peer.reach,
            leap_indicator: peer.timestate.last_packet.leap(),
            root_delay: peer.timestate.last_packet.root_delay(),
            root_dispersion: peer.timestate.last_packet.root_dispersion(),
            poll_interval: peer.last_poll_interval,
        }
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
    NewMeasurement(PeerSnapshot),
}

impl Peer {
    #[instrument]
    pub fn new(
        our_id: ReferenceId,
        peer_id: ReferenceId,
        local_clock_time: NtpInstant,
        system_config: &SystemConfig,
    ) -> Self {
        // we initialize with the current time so that we're in the correct epoch.
        let time = local_clock_time;

        Self {
            last_poll_interval: system_config.poll_limits.min,
            backoff_interval: system_config.poll_limits.min,
            remote_min_poll_interval: system_config.poll_limits.min,

            current_request_identifier: None,
            our_id,
            peer_id,
            reach: Default::default(),

            timestate: PeerTimeState {
                statistics: Default::default(),
                last_measurements: LastMeasurements::new(time),
                last_packet: Default::default(),
                time,
            },
        }
    }

    pub fn current_poll_interval(&self, system: SystemSnapshot) -> PollInterval {
        system
            .poll_interval
            .max(self.backoff_interval)
            .max(self.remote_min_poll_interval)
    }

    pub fn generate_poll_message(
        &mut self,
        system: SystemSnapshot,
        system_config: &SystemConfig,
    ) -> NtpPacket<'static> {
        self.reach.poll();

        let poll_interval = self.current_poll_interval(system);
        let (packet, identifier) = NtpPacket::poll_message(poll_interval);
        self.current_request_identifier = Some((identifier, NtpInstant::now() + POLL_WINDOW));

        // Ensure we don't spam the remote with polls if it is not reachable
        self.backoff_interval = poll_interval.inc(system_config.poll_limits);

        packet
    }

    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(self, system, system_config), fields(peer = debug(self.peer_id)))]
    pub fn handle_incoming(
        &mut self,
        system: SystemSnapshot,
        system_config: &SystemConfig,
        message: NtpPacket,
        local_clock_time: NtpInstant,
        send_time: NtpTimestamp,
        recv_time: NtpTimestamp,
    ) -> Result<Update, IgnoreReason> {
        let request_identifier = match self.current_request_identifier {
            Some((next_expected_origin, validity)) if validity >= NtpInstant::now() => {
                next_expected_origin
            }
            _ => {
                debug!("Received old/unexpected packet from peer");
                return Err(IgnoreReason::InvalidPacketTime);
            }
        };

        if !message.valid_server_response(request_identifier) {
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
                self.remote_min_poll_interval.inc(system_config.poll_limits),
                self.last_poll_interval,
            );
            warn!(?self.remote_min_poll_interval, "Peer requested rate limit");
            Err(IgnoreReason::KissIgnore)
        } else if message.is_kiss_rstr() || message.is_kiss_deny() {
            warn!("Peer denied service");
            // KISS packets may not have correct timestamps at all, handle them anyway
            Err(IgnoreReason::KissDemobilize)
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
            Ok(self.process_message(
                system,
                system_config,
                message,
                local_clock_time,
                send_time,
                recv_time,
            ))
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_message(
        &mut self,
        system: SystemSnapshot,
        system_config: &SystemConfig,
        message: NtpPacket,
        local_clock_time: NtpInstant,
        send_time: NtpTimestamp,
        recv_time: NtpTimestamp,
    ) -> Update {
        trace!("Packet accepted for processing");
        // For reachability, mark that we have had a response
        self.reach.received_packet();

        // Got a response, so no need for unreachability backoff
        self.backoff_interval = system_config.poll_limits.min;

        // we received this packet, and don't want to accept future ones with this next_expected_origin
        self.current_request_identifier = None;

        // generate a measurement
        let measurement = Measurement::from_packet(
            &message,
            send_time,
            recv_time,
            local_clock_time,
            system.precision,
        );

        match self
            .timestate
            .update(measurement, message, system, system_config)
        {
            None => Update::BareUpdate(PeerSnapshot::from_peer(self)),
            Some(_) => Update::NewMeasurement(PeerSnapshot::from_peer(self)),
        }
    }

    #[instrument(level="trace", skip(self), fields(peer = debug(self.peer_id)))]
    pub fn reset(&mut self) {
        // Reset timestate
        self.timestate.reset_measurements();

        // make sure in-flight messages are ignored
        self.current_request_identifier = None;

        info!(our_id = ?self.our_id, peer_id = ?self.peer_id, "Peer reset");
    }

    #[cfg(test)]
    pub(crate) fn test_peer(instant: NtpInstant) -> Self {
        Peer {
            last_poll_interval: PollInterval::default(),
            backoff_interval: PollInterval::default(),
            remote_min_poll_interval: PollInterval::default(),

            current_request_identifier: None,

            peer_id: ReferenceId::from_int(0),
            our_id: ReferenceId::from_int(0),
            reach: Reach::default(),

            timestate: PeerTimeState::test_timestate(instant),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::time_types::PollIntervalLimits;

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
    fn test_root_duration_sanity() {
        // Ensure root distance at least increases as it is supposed to
        // when changing the main measurement parameters

        let duration_1s = NtpDuration::from_fixed_int(1_0000_0000);
        let duration_2s = NtpDuration::from_fixed_int(2_0000_0000);

        // let timestamp_1s = NtpInstant::from_fixed_int(1_0000_0000);
        // let timestamp_2s = NtpInstant::from_fixed_int(2_0000_0000);

        let timestamp_0s = NtpInstant::now();
        let timestamp_1s = timestamp_0s + std::time::Duration::new(1, 0);
        let timestamp_2s = timestamp_0s + std::time::Duration::new(2, 0);

        let ft = FrequencyTolerance::ppm(15);

        let mut packet = NtpPacket::test();
        packet.set_root_delay(duration_1s);
        packet.set_root_dispersion(duration_1s);
        let reference = PeerTimeState {
            statistics: PeerStatistics {
                delay: duration_1s,
                dispersion: duration_1s,
                ..Default::default()
            },
            last_packet: packet.clone(),
            ..PeerTimeState::test_timestate(timestamp_1s)
        };

        assert!(
            reference.root_distance(timestamp_1s, ft) < reference.root_distance(timestamp_2s, ft)
        );

        let sample = PeerTimeState {
            statistics: PeerStatistics {
                delay: duration_2s,
                dispersion: duration_1s,
                ..Default::default()
            },
            last_packet: packet.clone(),
            ..PeerTimeState::test_timestate(timestamp_1s)
        };
        assert!(reference.root_distance(timestamp_1s, ft) < sample.root_distance(timestamp_1s, ft));

        let sample = PeerTimeState {
            statistics: PeerStatistics {
                delay: duration_1s,
                dispersion: duration_2s,
                ..Default::default()
            },
            last_packet: packet.clone(),
            ..PeerTimeState::test_timestate(timestamp_1s)
        };
        assert!(reference.root_distance(timestamp_1s, ft) < sample.root_distance(timestamp_1s, ft));

        let sample = PeerTimeState {
            statistics: PeerStatistics {
                delay: duration_1s,
                dispersion: duration_1s,
                ..Default::default()
            },
            last_packet: packet.clone(),
            ..PeerTimeState::test_timestate(timestamp_0s)
        };
        assert!(reference.root_distance(timestamp_1s, ft) < sample.root_distance(timestamp_1s, ft));

        packet.set_root_delay(duration_2s);
        let sample = PeerTimeState {
            statistics: PeerStatistics {
                delay: duration_1s,
                dispersion: duration_1s,
                ..Default::default()
            },
            last_packet: packet.clone(),
            ..PeerTimeState::test_timestate(timestamp_1s)
        };
        packet.set_root_delay(duration_1s);
        assert!(reference.root_distance(timestamp_1s, ft) < sample.root_distance(timestamp_1s, ft));

        packet.set_root_dispersion(duration_2s);
        let sample = PeerTimeState {
            statistics: PeerStatistics {
                delay: duration_1s,
                dispersion: duration_1s,
                ..Default::default()
            },
            last_packet: packet.clone(),
            ..PeerTimeState::test_timestate(timestamp_1s)
        };
        packet.set_root_dispersion(duration_1s);
        assert!(reference.root_distance(timestamp_1s, ft) < sample.root_distance(timestamp_1s, ft));

        let sample = PeerTimeState {
            statistics: PeerStatistics {
                delay: duration_1s,
                dispersion: duration_1s,
                ..Default::default()
            },
            last_packet: packet.clone(),
            ..PeerTimeState::test_timestate(timestamp_1s)
        };

        assert_eq!(
            reference.root_distance(timestamp_1s, ft),
            sample.root_distance(timestamp_1s, ft)
        );
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

        let local_clock_time = NtpInstant::now();
        let ft = FrequencyTolerance::ppm(15);
        let dt = NtpDuration::ONE;
        let system_poll = PollIntervalLimits::default().min;

        let mut peer = Peer::test_peer(local_clock_time);

        macro_rules! accept {
            () => {{
                let snapshot = PeerSnapshot::from_peer(&peer);
                snapshot.accept_synchronization(local_clock_time, ft, dt, system_poll, 16)
            }};
        }

        // by default, the packet id and the peer's id are the same, indicating a loop
        assert_eq!(accept!(), Err(Loop));

        peer.our_id = ReferenceId::from_int(42);

        assert_eq!(accept!(), Err(ServerUnreachable));

        peer.reach.received_packet();

        assert_eq!(accept!(), Ok(()));

        peer.timestate
            .last_packet
            .set_leap(NtpLeapIndicator::Unknown);
        assert_eq!(accept!(), Err(Stratum));

        peer.timestate
            .last_packet
            .set_leap(NtpLeapIndicator::NoWarning);
        peer.timestate.last_packet.set_stratum(42);
        assert_eq!(accept!(), Err(Stratum));

        peer.timestate.last_packet.set_stratum(0);

        peer.timestate.last_packet.set_root_dispersion(dt * 2);
        assert_eq!(accept!(), Err(Distance));
    }

    #[test]
    fn test_poll_interval() {
        let base = NtpInstant::now();
        let mut peer = Peer::test_peer(base);
        let mut system = SystemSnapshot::default();

        assert!(peer.current_poll_interval(system) >= peer.remote_min_poll_interval);
        assert!(peer.current_poll_interval(system) >= system.poll_interval);

        system.poll_interval = PollIntervalLimits::default().max;

        assert!(peer.current_poll_interval(system) >= peer.remote_min_poll_interval);
        assert!(peer.current_poll_interval(system) >= system.poll_interval);

        system.poll_interval = PollIntervalLimits::default().min;
        peer.remote_min_poll_interval = PollIntervalLimits::default().max;

        assert!(peer.current_poll_interval(system) >= peer.remote_min_poll_interval);
        assert!(peer.current_poll_interval(system) >= system.poll_interval);

        peer.remote_min_poll_interval = PollIntervalLimits::default().min;

        let prev = peer.current_poll_interval(system);
        let packet = peer.generate_poll_message(system, &SystemConfig::default());
        assert!(peer.current_poll_interval(system) > prev);
        let mut response = NtpPacket::test();
        response.set_mode(NtpAssociationMode::Server);
        response.set_stratum(1);
        response.set_origin_timestamp(packet.transmit_timestamp());
        assert!(peer
            .handle_incoming(
                system,
                &SystemConfig::default(),
                response,
                base,
                NtpTimestamp::default(),
                NtpTimestamp::default()
            )
            .is_ok());
        assert_eq!(peer.current_poll_interval(system), prev);

        let prev = peer.current_poll_interval(system);
        let packet = peer.generate_poll_message(system, &SystemConfig::default());
        assert!(peer.current_poll_interval(system) > prev);
        let mut response = NtpPacket::test();
        response.set_mode(NtpAssociationMode::Server);
        response.set_stratum(0);
        response.set_origin_timestamp(packet.transmit_timestamp());
        response.set_reference_id(ReferenceId::KISS_RATE);
        assert!(peer
            .handle_incoming(
                system,
                &SystemConfig::default(),
                response,
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
        let mut peer = Peer::test_peer(base);

        let system = SystemSnapshot::default();
        let outgoing = peer.generate_poll_message(system, &SystemConfig::default());
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
                &SystemConfig::default(),
                packet.clone(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(400)
            )
            .is_ok());
        assert_eq!(peer.timestate.last_packet, packet);
        assert!(peer
            .handle_incoming(
                system,
                &SystemConfig::default(),
                packet,
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(500)
            )
            .is_err());
    }

    #[test]
    fn test_stratum_checks() {
        let base = NtpInstant::now();
        let mut peer = Peer::test_peer(base);

        let system = SystemSnapshot::default();
        let outgoing = peer.generate_poll_message(system, &SystemConfig::default());
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
                &SystemConfig::default(),
                packet.clone(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(500)
            )
            .is_err());

        packet.set_stratum(0);
        assert!(peer
            .handle_incoming(
                system,
                &SystemConfig::default(),
                packet.clone(),
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(500)
            )
            .is_err());
    }

    #[test]
    fn test_handle_kod() {
        let base = NtpInstant::now();
        let mut peer = Peer::test_peer(base);

        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        packet.set_reference_id(ReferenceId::KISS_RSTR);
        packet.set_mode(NtpAssociationMode::Server);
        assert!(!matches!(
            peer.handle_incoming(
                system,
                &SystemConfig::default(),
                packet,
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(100)
            ),
            Err(IgnoreReason::KissDemobilize)
        ));

        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        let outgoing = peer.generate_poll_message(system, &SystemConfig::default());
        packet.set_reference_id(ReferenceId::KISS_RSTR);
        packet.set_origin_timestamp(outgoing.transmit_timestamp());
        packet.set_mode(NtpAssociationMode::Server);
        assert!(matches!(
            peer.handle_incoming(
                system,
                &SystemConfig::default(),
                packet,
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
                &SystemConfig::default(),
                packet,
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(100)
            ),
            Err(IgnoreReason::KissDemobilize)
        ));

        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        let outgoing = peer.generate_poll_message(system, &SystemConfig::default());
        packet.set_reference_id(ReferenceId::KISS_DENY);
        packet.set_origin_timestamp(outgoing.transmit_timestamp());
        packet.set_mode(NtpAssociationMode::Server);
        assert!(matches!(
            peer.handle_incoming(
                system,
                &SystemConfig::default(),
                packet,
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
                &SystemConfig::default(),
                packet,
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
        let outgoing = peer.generate_poll_message(system, &SystemConfig::default());
        packet.set_reference_id(ReferenceId::KISS_RATE);
        packet.set_origin_timestamp(outgoing.transmit_timestamp());
        packet.set_mode(NtpAssociationMode::Server);
        assert!(peer
            .handle_incoming(
                system,
                &SystemConfig::default(),
                packet,
                base + Duration::from_secs(1),
                NtpTimestamp::from_fixed_int(0),
                NtpTimestamp::from_fixed_int(100)
            )
            .is_err());
        assert!(peer.remote_min_poll_interval > old_poll_interval);
        assert!(peer.remote_min_poll_interval >= old_remote_interval);
    }
}
