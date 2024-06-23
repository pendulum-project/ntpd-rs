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
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::{
    io::Cursor,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tracing::{debug, info, instrument, trace, warn};

const MAX_STRATUM: u8 = 16;
const POLL_WINDOW: std::time::Duration = std::time::Duration::from_secs(5);
const STARTUP_TRIES_THRESHOLD: usize = 3;

pub struct SourceNtsData {
    pub(crate) cookies: CookieStash,
    // Note: we use Box<dyn Cipher> to support the use
    // of multiple different ciphers, that might differ
    // in the key information they need to keep.
    pub(crate) c2s: Box<dyn Cipher>,
    pub(crate) s2c: Box<dyn Cipher>,
}

#[cfg(any(test, feature = "__internal-test"))]
impl SourceNtsData {
    pub fn get_cookie(&mut self) -> Option<Vec<u8>> {
        self.cookies.get()
    }

    pub fn get_keys(self) -> (Box<dyn Cipher>, Box<dyn Cipher>) {
        (self.c2s, self.s2c)
    }
}

impl std::fmt::Debug for SourceNtsData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceNtsData")
            .field("cookies", &self.cookies)
            .finish()
    }
}

#[derive(Debug)]
pub struct NtpSource {
    nts: Option<Box<SourceNtsData>>,

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
    reach: Reach,
    tries: usize,

    source_defaults_config: SourceDefaultsConfig,

    buffer: [u8; 1024],

    protocol_version: ProtocolVersion,

    #[cfg(feature = "ntpv5")]
    // TODO we only need this if we run as a server
    bloom_filter: RemoteBloomFilter,
}

#[derive(Debug, Copy, Clone)]
pub struct GpsMeasurement {
    pub measurementnoise: NtpDuration,
    pub offset: NtpDuration,
}
#[derive(Debug, Copy, Clone)]
pub struct PpsMeasurement {
    pub measurementnoise: NtpDuration,
    pub offset: NtpDuration,
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

    // New fields from GpsMeasurement
    pub gps: Option<GpsMeasurement>,
    // New fields from PpsMeasurement
    pub pps: Option<PpsMeasurement>,
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
            gps: None,
            pps: None,
        }
    }

    pub fn from_gps(
        offset: NtpDuration,
        local_clock_time: NtpInstant,
        timestamp: NtpTimestamp,
        measuremet_noise: f64,
    ) -> Self {
        Self {
            delay: NtpDuration::default(),
            offset: NtpDuration::default(),
            transmit_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            localtime: timestamp,
            monotime: local_clock_time,
            stratum: 1,
            root_delay: NtpDuration::default(),
            root_dispersion: NtpDuration::default(),
            leap: NtpLeapIndicator::NoWarning,
            precision: 0,
            gps: Some(GpsMeasurement {
                measurementnoise: NtpDuration::from_seconds(measuremet_noise),
                offset,
            }),
            pps: None,
        }
    }
    pub fn from_pps(
        offset: NtpDuration,
        local_clock_time: NtpInstant,
        ntp_timestamp: NtpTimestamp,
        measurement_noise: f64,
    ) -> Self {
        Self {
            delay: NtpDuration::default(),
            offset: NtpDuration::default(),
            transmit_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            localtime: ntp_timestamp,
            monotime: local_clock_time,

            stratum: 1,
            root_delay: NtpDuration::default(),
            root_dispersion: NtpDuration::default(),
            leap: NtpLeapIndicator::NoWarning,
            precision: 0,
            gps: None,
            pps: Some(PpsMeasurement {
                measurementnoise: NtpDuration::from_seconds(measurement_noise),
                offset,
            }),
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

    /// We have just received a packet, so the source is definitely reachable
    pub(crate) fn received_packet(&mut self) {
        self.0 |= 1;
    }

    /// A packet received some number of poll intervals ago is decreasingly relevant for
    /// determining that a source is still reachable. We discount the packets received so far.
    fn poll(&mut self) {
        self.0 <<= 1;
    }

    /// Number of polls since the last message we received
    pub fn unanswered_polls(&self) -> u32 {
        self.0.trailing_zeros()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NtpSourceSnapshot {
    pub source_addr: SocketAddr,

    pub source_id: ReferenceId,

    pub poll_interval: PollInterval,
    pub reach: Reach,

    pub stratum: u8,
    pub reference_id: ReferenceId,

    pub protocol_version: ProtocolVersion,

    #[cfg(feature = "ntpv5")]
    pub bloom_filter: Option<BloomFilter>,
}

impl NtpSourceSnapshot {
    pub fn accept_synchronization(
        &self,
        local_stratum: u8,
        local_ips: &[IpAddr],
        #[cfg_attr(not(feature = "ntpv5"), allow(unused_variables))] system: &SystemSnapshot,
    ) -> Result<(), AcceptSynchronizationError> {
        use AcceptSynchronizationError::*;

        if self.stratum >= local_stratum {
            info!(
                source_stratum = self.stratum,
                own_stratum = local_stratum,
                "Source rejected due to invalid stratum. The stratum of a source must be lower than the own stratum",
            );
            return Err(Stratum);
        }

        // Detect whether the remote uses us as their main time reference.
        // if so, we shouldn't sync to them as that would create a loop.
        // Note, this can only ever be an issue if the source is not using
        // hardware as its source, so ignore reference_id if stratum is 1.

        if self.stratum != 1
            && local_ips
                .iter()
                .any(|ip| ReferenceId::from_ip(*ip) == self.source_id)
        {
            info!("Source rejected because of detected synchronization loop (ref id)");
            return Err(Loop);
        }

        #[cfg(feature = "ntpv5")]
        match self.bloom_filter {
            Some(filter) if filter.contains_id(&system.server_id) => {
                info!("Source rejected because of detected synchronization loop (bloom filter)");
                return Err(Loop);
            }
            _ => {}
        }

        // An unreachable error occurs if the server is unreachable.
        if !self.reach.is_reachable() {
            info!("Source is unreachable");
            return Err(ServerUnreachable);
        }

        Ok(())
    }

    pub fn from_source(source: &NtpSource) -> Self {
        Self {
            source_addr: source.source_addr,
            source_id: source.source_id,
            stratum: source.stratum,
            reference_id: source.reference_id,
            reach: source.reach,
            poll_interval: source.last_poll_interval,
            protocol_version: source.protocol_version,
            #[cfg(feature = "ntpv5")]
            bloom_filter: source.bloom_filter.full_filter().copied(),
        }
    }
}

#[cfg(feature = "__internal-test")]
pub fn source_snapshot() -> NtpSourceSnapshot {
    use std::net::Ipv4Addr;

    let mut reach = crate::source::Reach::default();
    reach.received_packet();

    NtpSourceSnapshot {
        source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        source_id: ReferenceId::from_int(0),
        stratum: 0,
        reference_id: ReferenceId::from_int(0),

        reach,
        poll_interval: crate::time_types::PollIntervalLimits::default().min,
        protocol_version: Default::default(),
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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

#[derive(Debug, Copy, Clone)]
pub struct NtpSourceUpdate {
    pub(crate) snapshot: NtpSourceSnapshot,
    pub(crate) measurement: Option<Measurement>,
}

#[cfg(feature = "__internal-test")]
impl NtpSourceUpdate {
    pub fn snapshot(snapshot: NtpSourceSnapshot) -> Self {
        NtpSourceUpdate {
            snapshot,
            measurement: None,
        }
    }

    pub fn measurement(snapshot: NtpSourceSnapshot, measurement: Measurement) -> Self {
        NtpSourceUpdate {
            snapshot,
            measurement: Some(measurement),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum NtpSourceAction {
    /// Send a message over the network. When this is issued, the network port maybe changed.
    Send(Vec<u8>),
    /// Send an update to [`System`](crate::system::System)
    UpdateSystem(NtpSourceUpdate),
    /// Call [`NtpSource::handle_timer`] after given duration
    SetTimer(Duration),
    /// A complete reset of the connection is necessary, including a potential new NTSKE client session and/or DNS lookup.
    Reset,
    /// We must stop talking to this particular server.
    Demobilize,
}

#[derive(Debug)]
pub struct NtpSourceActionIterator {
    iter: <Vec<NtpSourceAction> as IntoIterator>::IntoIter,
}

impl Default for NtpSourceActionIterator {
    fn default() -> Self {
        Self {
            iter: vec![].into_iter(),
        }
    }
}

impl Iterator for NtpSourceActionIterator {
    type Item = NtpSourceAction;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl NtpSourceActionIterator {
    fn from(data: Vec<NtpSourceAction>) -> Self {
        Self {
            iter: data.into_iter(),
        }
    }
}

macro_rules! actions {
    [$($action:expr),*] => {
        {
            NtpSourceActionIterator::from(vec![$($action),*])
        }
    }
}

impl NtpSource {
    #[instrument]
    pub fn new(
        source_addr: SocketAddr,
        source_defaults_config: SourceDefaultsConfig,
        protocol_version: ProtocolVersion,
    ) -> (Self, NtpSourceActionIterator) {
        (
            Self {
                nts: None,

                last_poll_interval: source_defaults_config.poll_interval_limits.min,
                remote_min_poll_interval: source_defaults_config.poll_interval_limits.min,

                current_request_identifier: None,
                source_id: ReferenceId::from_ip(source_addr.ip()),
                source_addr,
                reach: Default::default(),
                tries: 0,

                stratum: 16,
                reference_id: ReferenceId::NONE,

                source_defaults_config,

                buffer: [0; 1024],

                protocol_version, // TODO make this configurable

                #[cfg(feature = "ntpv5")]
                bloom_filter: RemoteBloomFilter::new(16).expect("16 is a valid chunk size"),
            },
            actions!(NtpSourceAction::SetTimer(Duration::from_secs(0))),
        )
    }

    #[instrument]
    pub fn new_nts(
        source_addr: SocketAddr,
        source_defaults_config: SourceDefaultsConfig,
        protocol_version: ProtocolVersion,
        nts: Box<SourceNtsData>,
    ) -> (Self, NtpSourceActionIterator) {
        let (base, actions) = Self::new(source_addr, source_defaults_config, protocol_version);
        (
            Self {
                nts: Some(nts),
                ..base
            },
            actions,
        )
    }

    pub fn current_poll_interval(&self, system: SystemSnapshot) -> PollInterval {
        system
            .time_snapshot
            .poll_interval
            .max(self.remote_min_poll_interval)
    }

    #[cfg_attr(not(feature = "ntpv5"), allow(unused_mut))]
    pub fn handle_timer(&mut self, system: SystemSnapshot) -> NtpSourceActionIterator {
        if !self.reach.is_reachable() && self.tries >= STARTUP_TRIES_THRESHOLD {
            return actions!(NtpSourceAction::Reset);
        }

        self.reach.poll();
        self.tries = self.tries.saturating_add(1);

        let poll_interval = self.current_poll_interval(system);
        let (mut packet, identifier) = match &mut self.nts {
            Some(nts) => {
                let Some(cookie) = nts.cookies.get() else {
                    return actions!(NtpSourceAction::Reset);
                };
                // Do ensure we don't exceed the buffer size
                // when requesting new cookies. We keep 350
                // bytes of margin for header, ids, extension
                // field headers and signature.
                let new_cookies = nts
                    .cookies
                    .gap()
                    .min(((self.buffer.len() - 300) / cookie.len()).min(u8::MAX as usize) as u8);
                match self.protocol_version {
                    ProtocolVersion::V4 => {
                        NtpPacket::nts_poll_message(&cookie, new_cookies, poll_interval)
                    }
                    #[cfg(feature = "ntpv5")]
                    ProtocolVersion::V4UpgradingToV5 { .. } | ProtocolVersion::V5 => {
                        NtpPacket::nts_poll_message_v5(&cookie, new_cookies, poll_interval)
                    }
                }
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

        #[cfg(feature = "ntpv5")]
        if let NtpHeader::V5(header) = packet.header() {
            let req_ef = self.bloom_filter.next_request(header.client_cookie);
            packet.push_additional(ExtensionField::ReferenceIdRequest(req_ef));
        }

        // update the poll interval
        self.last_poll_interval = poll_interval;

        let snapshot = NtpSourceSnapshot::from_source(self);

        // Write packet to buffer
        let mut cursor: Cursor<&mut [u8]> = Cursor::new(&mut self.buffer);
        packet
            .serialize(
                &mut cursor,
                &self.nts.as_ref().map(|nts| nts.c2s.as_ref()),
                None,
            )
            .expect("Internal error: could not serialize packet");
        let used = cursor.position();
        let result = &cursor.into_inner()[..used as usize];

        actions!(
            NtpSourceAction::Send(result.into()),
            NtpSourceAction::UpdateSystem(NtpSourceUpdate {
                snapshot,
                measurement: None
            }),
            // randomize the poll interval a little to make it harder to predict poll requests
            NtpSourceAction::SetTimer(
                poll_interval
                    .as_system_duration()
                    .mul_f64(thread_rng().gen_range(1.01..=1.05))
            )
        )
    }

    #[instrument(skip(self, system), fields(source = debug(self.source_id)))]
    pub fn handle_incoming(
        &mut self,
        system: SystemSnapshot,
        message: &[u8],
        local_clock_time: NtpInstant,
        send_time: NtpTimestamp,
        recv_time: NtpTimestamp,
    ) -> NtpSourceActionIterator {
        let message =
            match NtpPacket::deserialize(message, &self.nts.as_ref().map(|nts| nts.s2c.as_ref())) {
                Ok((packet, _)) => packet,
                Err(e) => {
                    warn!("received invalid packet: {}", e);
                    return actions!();
                }
            };

        if message.version() != self.protocol_version.expected_incoming_version() {
            return actions!();
        }

        let request_identifier = match self.current_request_identifier {
            Some((next_expected_origin, validity)) if validity >= NtpInstant::now() => {
                next_expected_origin
            }
            _ => {
                debug!("Received old/unexpected packet from source");
                return actions!();
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
            debug!("Received old/unexpected packet from source");
            actions!()
        } else if message.is_kiss_rate() {
            // KISS packets may not have correct timestamps at all, handle them anyway
            self.remote_min_poll_interval = Ord::max(
                self.remote_min_poll_interval
                    .inc(self.source_defaults_config.poll_interval_limits),
                self.last_poll_interval,
            );
            warn!(?self.remote_min_poll_interval, "Source requested rate limit");
            actions!()
        } else if message.is_kiss_rstr() || message.is_kiss_deny() {
            warn!("Source denied service");
            // KISS packets may not have correct timestamps at all, handle them anyway
            actions!(NtpSourceAction::Demobilize)
        } else if message.is_kiss_ntsn() {
            warn!("Received nts not-acknowledge");
            // as these can be easily faked, we dont immediately give up on receiving
            // a response.
            actions!()
        } else if message.is_kiss() {
            warn!("Unrecognized KISS Message from source");
            // Ignore unrecognized control messages
            actions!()
        } else if message.stratum() > MAX_STRATUM {
            // A servers stratum should be between 1 and MAX_STRATUM (16) inclusive.
            warn!(
                "Received message from server with excessive stratum {}",
                message.stratum()
            );
            actions!()
        } else if message.mode() != NtpAssociationMode::Server {
            // we currently only support a client <-> server association
            warn!("Received packet with invalid mode");
            actions!()
        } else {
            self.process_message(system, message, local_clock_time, send_time, recv_time)
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
    ) -> NtpSourceActionIterator {
        trace!("Packet accepted for processing");
        // For reachability, mark that we have had a response
        self.reach.received_packet();

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

            // Update our bloom filter (we need separate branches due to types
            let bloom_responses = if self.nts.is_some() {
                message
                    .authenticated_extension_fields()
                    .filter_map(|ef| match ef {
                        ExtensionField::ReferenceIdResponse(response) => Some(response),
                        _ => None,
                    })
                    .next()
            } else {
                message
                    .untrusted_extension_fields()
                    .filter_map(|ef| match ef {
                        ExtensionField::ReferenceIdResponse(response) => Some(response),
                        _ => None,
                    })
                    .next()
            };

            if let Some(ref_id) = bloom_responses {
                let result = self
                    .bloom_filter
                    .handle_response(header.client_cookie, ref_id);
                if let Err(err) = result {
                    info!(?err, "Invalid ReferenceIdResponse from source, ignoring...")
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
        actions!(NtpSourceAction::UpdateSystem(NtpSourceUpdate {
            snapshot: NtpSourceSnapshot::from_source(self),
            measurement: Some(measurement),
        }))
    }

    #[cfg(test)]
    pub(crate) fn test_ntp_source() -> Self {
        use std::net::Ipv4Addr;

        NtpSource {
            nts: None,

            last_poll_interval: PollInterval::default(),
            remote_min_poll_interval: PollInterval::default(),

            current_request_identifier: None,

            source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            source_id: ReferenceId::from_int(0),
            reach: Reach::default(),
            tries: 0,

            stratum: 0,
            reference_id: ReferenceId::from_int(0),

            source_defaults_config: SourceDefaultsConfig::default(),

            buffer: [0; 1024],

            protocol_version: Default::default(),

            #[cfg(feature = "ntpv5")]
            bloom_filter: RemoteBloomFilter::new(16).unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pps_source_new() {
        let (pps_source, action_iter) = PpsSource::new();
        let actions: Vec<_> = action_iter.collect();
        assert_eq!(actions.len(), 1);
        if let PpsSourceAction::SetTimer(duration) = &actions[0] {
            assert_eq!(*duration, Duration::from_secs(0));
        } else {
            panic!("Expected SetTimer action");
        }
    }

    #[test]
    fn test_pps_source_handle_incoming() {
        let mut pps_source = PpsSource::new().0;
        let local_clock_time = NtpInstant::now();
        let offset = NtpDuration::from_seconds(0.0);
        let ntp_timestamp = NtpTimestamp::from_fixed_int(0);
        let measurement_noise = 0.0;

        let action_iter =
            pps_source.handle_incoming(local_clock_time, offset, ntp_timestamp, measurement_noise);
        let actions: Vec<_> = action_iter.collect();
        assert_eq!(actions.len(), 1);
        if let PpsSourceAction::UpdateSystem(update) = &actions[0] {
            assert!(update.measurement.is_some());
        } else {
            panic!("Expected UpdateSystem action");
        }
    }

    #[test]
    fn test_pps_source_action_set_timer() {
        let duration = Duration::from_secs(10);
        let action = PpsSourceAction::SetTimer(duration);
        if let PpsSourceAction::SetTimer(d) = action {
            assert_eq!(d, duration);
        } else {
            panic!("Expected SetTimer action");
        }
    }

    #[test]
    fn test_pps_source_action_reset() {
        let action = PpsSourceAction::Reset;
        match action {
            PpsSourceAction::Reset => (),
            _ => panic!("Expected Reset action"),
        }
    }

    #[test]
    fn test_pps_source_action_demobilize() {
        let action = PpsSourceAction::Demobilize;
        match action {
            PpsSourceAction::Demobilize => (),
            _ => panic!("Expected Demobilize action"),
        }
    }

    #[test]
    fn test_pps_source_action_send() {
        let action = PpsSourceAction::Send();
        match action {
            PpsSourceAction::Send() => (),
            _ => panic!("Expected Send action"),
        }
    }

    #[test]
    fn test_pps_source_default_action_iterator() {
        let action_iter = PpsSourceActionIterator::default();
        assert_eq!(action_iter.count(), 0);
    }
}
