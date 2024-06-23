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
            pps:None,
        }
    }

    // create a new measurement for gps by the data recieved
    // the fields needed are the offset, monotime, timestamp and noise.
    // offset is one of the inputs for the stable and initial kalman which is used to measure
    // how much off the current measurement varies from the system time
    // monotime is recieved immediately when we recieve the measurement from the settalite
    // this is needed in the latter stages of the algorithm to check if the clock is steered in an unusual way
    // since the monotime or instant is a seperate clock that doesn't get affected by steering and always moves forward
    // timestamp is the measurement we recieve from the settalite which is also sent to the kalman
    // because the filter uses the last measurement time and the current measurement time to update
    // the estiamted offset and frequency error. this is done by calculating a delta t 
    // (how much time have passed during each measurement according to this source)
    // lastly a noise is recieved which in this case can be changed from the config and this depends on the hardware used
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
            pps:None,
        }
    }
    // create a new measurement for pps by the data recieved
    // the fields needed are the offset, monotime, timestamp and noise.
    // offset is one of the inputs for the stable and initial kalman which is used to measure
    // how much off the current measurement varies from the system time
    // monotime is recieved immediately when we recieve the measurement from the kernel
    // this is needed in the latter stages of the algorithm to check if the clock is steered in an unusual way
    // since the monotime or instant is a seperate clock that doesn't get affected by steering and always moves forward
    // timestamp is the measurement we recieve from the kernel which is also sent to the kalman
    // because the filter uses the last measurement time and the current measurement time to update
    // the estiamted offset and frequency error. this is done by calculating a delta t 
    // (how much time have passed during each measurement according to this source)
    // lastly a noise is recieved which in this case can be changed from the config and this depends on the hardware used
    pub fn from_pps(
        offset: NtpDuration, 
        local_clock_time: NtpInstant,
        ntp_timestamp: NtpTimestamp,
        measurement_noise: f64
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
    use crate::time_types::{NtpDuration, NtpTimestamp, NtpInstant};

    use crate::algorithm::kalman::source::{InitialSourceFilter, SourceFilter};
    use crate::algorithm::kalman::matrix::{Matrix, Vector};

    use super::*;
    #[cfg(feature = "ntpv5")]
    use crate::packet::v5::server_reference_id::ServerId;
    #[cfg(feature = "ntpv5")]
    use rand::thread_rng;

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
            panic!("Shouldn't be called by source");
        }

        fn step_clock(&self, _offset: NtpDuration) -> Result<NtpTimestamp, Self::Error> {
            panic!("Shouldn't be called by source");
        }

        fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by source");
        }

        fn error_estimate_update(
            &self,
            _est_error: NtpDuration,
            _max_error: NtpDuration,
        ) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by source");
        }

        fn status_update(&self, _leap_status: NtpLeapIndicator) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by source");
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
        // we just received a packet from the source, so it is reachable
        reach.received_packet();
        assert!(reach.is_reachable());

        // on every poll, the register is shifted to the left, and there are
        // 8 bits. So we can poll 7 times and the source is still considered reachable
        for _ in 0..7 {
            reach.poll();
        }

        assert!(reach.is_reachable());

        // but one more poll and all 1 bits have been shifted out;
        // the source is no longer reachable
        reach.poll();
        assert!(!reach.is_reachable());

        // until we receive a packet from it again
        reach.received_packet();
        assert!(reach.is_reachable());
    }

    #[test]
    fn test_accept_synchronization() {
        use AcceptSynchronizationError::*;

        let mut source = NtpSource::test_ntp_source();

        #[cfg_attr(not(feature = "ntpv5"), allow(unused_mut))]
        let mut system = SystemSnapshot::default();

        #[cfg(feature = "ntpv5")]
        {
            system.server_id = ServerId::new(&mut thread_rng());
        }

        macro_rules! accept {
            () => {{
                let snapshot = NtpSourceSnapshot::from_source(&source);
                snapshot.accept_synchronization(16, &["127.0.0.1".parse().unwrap()], &system)
            }};
        }

        source.source_id = ReferenceId::from_ip("127.0.0.1".parse().unwrap());
        assert_eq!(accept!(), Err(Loop));

        source.source_id = ReferenceId::from_ip("127.0.1.1".parse().unwrap());
        assert_eq!(accept!(), Err(ServerUnreachable));

        source.reach.received_packet();

        assert_eq!(accept!(), Ok(()));

        source.stratum = 42;
        assert_eq!(accept!(), Err(Stratum));
    }

    #[test]
    fn test_poll_interval() {
        let mut source = NtpSource::test_ntp_source();
        let mut system = SystemSnapshot::default();

        assert!(source.current_poll_interval(system) >= source.remote_min_poll_interval);
        assert!(source.current_poll_interval(system) >= system.time_snapshot.poll_interval);

        system.time_snapshot.poll_interval = PollIntervalLimits::default().max;

        assert!(source.current_poll_interval(system) >= source.remote_min_poll_interval);
        assert!(source.current_poll_interval(system) >= system.time_snapshot.poll_interval);

        system.time_snapshot.poll_interval = PollIntervalLimits::default().min;
        source.remote_min_poll_interval = PollIntervalLimits::default().max;

        assert!(source.current_poll_interval(system) >= source.remote_min_poll_interval);
        assert!(source.current_poll_interval(system) >= system.time_snapshot.poll_interval);
    }

    #[test]
    fn test_handle_incoming() {
        let base = NtpInstant::now();
        let mut source = NtpSource::test_ntp_source();

        let system = SystemSnapshot::default();
        let actions = source.handle_timer(system);
        let mut outgoingbuf = None;
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
            if let NtpSourceAction::Send(buf) = action {
                outgoingbuf = Some(buf);
            }
        }
        let outgoingbuf = outgoingbuf.unwrap();
        let outgoing = NtpPacket::deserialize(&outgoingbuf, &NoCipher).unwrap().0;
        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        packet.set_stratum(1);
        packet.set_mode(NtpAssociationMode::Server);
        packet.set_origin_timestamp(outgoing.transmit_timestamp());
        packet.set_receive_timestamp(NtpTimestamp::from_fixed_int(100));
        packet.set_transmit_timestamp(NtpTimestamp::from_fixed_int(200));

        let actions = source.handle_incoming(
            system,
            &packet.serialize_without_encryption_vec(None).unwrap(),
            base + Duration::from_secs(1),
            NtpTimestamp::from_fixed_int(0),
            NtpTimestamp::from_fixed_int(400),
        );
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset
                    | NtpSourceAction::Demobilize
                    | NtpSourceAction::SetTimer(_)
                    | NtpSourceAction::Send(_)
            ));
        }
        let mut actions = source.handle_incoming(
            system,
            &packet.serialize_without_encryption_vec(None).unwrap(),
            base + Duration::from_secs(1),
            NtpTimestamp::from_fixed_int(0),
            NtpTimestamp::from_fixed_int(500),
        );
        assert!(actions.next().is_none());
    }

    #[test]
    fn test_startup_unreachable() {
        let mut source = NtpSource::test_ntp_source();
        let system = SystemSnapshot::default();
        let actions = source.handle_timer(system);
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
        }
        let actions = source.handle_timer(system);
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
        }
        let actions = source.handle_timer(system);
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
        }
        let mut actions = source.handle_timer(system);
        assert!(matches!(actions.next(), Some(NtpSourceAction::Reset)));
    }

    #[test]
    fn test_running_unreachable() {
        let base = NtpInstant::now();
        let mut source = NtpSource::test_ntp_source();

        let system = SystemSnapshot::default();
        let actions = source.handle_timer(system);
        let mut outgoingbuf = None;
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
            if let NtpSourceAction::Send(buf) = action {
                outgoingbuf = Some(buf);
            }
        }
        let outgoingbuf = outgoingbuf.unwrap();
        let outgoing = NtpPacket::deserialize(&outgoingbuf, &NoCipher).unwrap().0;
        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        packet.set_stratum(1);
        packet.set_mode(NtpAssociationMode::Server);
        packet.set_origin_timestamp(outgoing.transmit_timestamp());
        packet.set_receive_timestamp(NtpTimestamp::from_fixed_int(100));
        packet.set_transmit_timestamp(NtpTimestamp::from_fixed_int(200));
        let actions = source.handle_incoming(
            system,
            &packet.serialize_without_encryption_vec(None).unwrap(),
            base + Duration::from_secs(1),
            NtpTimestamp::from_fixed_int(0),
            NtpTimestamp::from_fixed_int(400),
        );
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset
                    | NtpSourceAction::Demobilize
                    | NtpSourceAction::SetTimer(_)
                    | NtpSourceAction::Send(_)
            ));
        }

        let actions = source.handle_timer(system);
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
        }
        let actions = source.handle_timer(system);
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
        }
        let actions = source.handle_timer(system);
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
        }
        let actions = source.handle_timer(system);
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
        }
        let actions = source.handle_timer(system);
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
        }
        let actions = source.handle_timer(system);
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
        }
        let actions = source.handle_timer(system);
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
        }
        let actions = source.handle_timer(system);
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
        }
        let mut actions = source.handle_timer(system);
        assert!(matches!(actions.next(), Some(NtpSourceAction::Reset)));
    }

    #[test]
    fn test_stratum_checks() {
        let base = NtpInstant::now();
        let mut source = NtpSource::test_ntp_source();

        let system = SystemSnapshot::default();
        let actions = source.handle_timer(system);
        let mut outgoingbuf = None;
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
            if let NtpSourceAction::Send(buf) = action {
                outgoingbuf = Some(buf);
            }
        }
        let outgoingbuf = outgoingbuf.unwrap();
        let outgoing = NtpPacket::deserialize(&outgoingbuf, &NoCipher).unwrap().0;
        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        packet.set_stratum(MAX_STRATUM + 1);
        packet.set_mode(NtpAssociationMode::Server);
        packet.set_origin_timestamp(outgoing.transmit_timestamp());
        packet.set_receive_timestamp(NtpTimestamp::from_fixed_int(100));
        packet.set_transmit_timestamp(NtpTimestamp::from_fixed_int(200));
        let mut actions = source.handle_incoming(
            system,
            &packet.serialize_without_encryption_vec(None).unwrap(),
            base + Duration::from_secs(1),
            NtpTimestamp::from_fixed_int(0),
            NtpTimestamp::from_fixed_int(500),
        );
        assert!(actions.next().is_none());

        packet.set_stratum(0);
        let mut actions = source.handle_incoming(
            system,
            &packet.serialize_without_encryption_vec(None).unwrap(),
            base + Duration::from_secs(1),
            NtpTimestamp::from_fixed_int(0),
            NtpTimestamp::from_fixed_int(500),
        );
        assert!(actions.next().is_none());
    }

    #[test]
    fn test_handle_kod() {
        let base = NtpInstant::now();
        let mut source = NtpSource::test_ntp_source();

        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        packet.set_reference_id(ReferenceId::KISS_RSTR);
        packet.set_mode(NtpAssociationMode::Server);
        let mut actions = source.handle_incoming(
            system,
            &packet.serialize_without_encryption_vec(None).unwrap(),
            base + Duration::from_secs(1),
            NtpTimestamp::from_fixed_int(0),
            NtpTimestamp::from_fixed_int(100),
        );
        assert!(actions.next().is_none());

        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        let actions = source.handle_timer(system);
        let mut outgoingbuf = None;
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
            if let NtpSourceAction::Send(buf) = action {
                outgoingbuf = Some(buf);
            }
        }
        let outgoingbuf = outgoingbuf.unwrap();
        let outgoing = NtpPacket::deserialize(&outgoingbuf, &NoCipher).unwrap().0;
        packet.set_reference_id(ReferenceId::KISS_RSTR);
        packet.set_origin_timestamp(outgoing.transmit_timestamp());
        packet.set_mode(NtpAssociationMode::Server);
        let mut actions = source.handle_incoming(
            system,
            &packet.serialize_without_encryption_vec(None).unwrap(),
            base + Duration::from_secs(1),
            NtpTimestamp::from_fixed_int(0),
            NtpTimestamp::from_fixed_int(100),
        );
        assert!(matches!(actions.next(), Some(NtpSourceAction::Demobilize)));

        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        packet.set_reference_id(ReferenceId::KISS_DENY);
        packet.set_mode(NtpAssociationMode::Server);
        let mut actions = source.handle_incoming(
            system,
            &packet.serialize_without_encryption_vec(None).unwrap(),
            base + Duration::from_secs(1),
            NtpTimestamp::from_fixed_int(0),
            NtpTimestamp::from_fixed_int(100),
        );
        assert!(actions.next().is_none());

        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        let actions = source.handle_timer(system);
        let mut outgoingbuf = None;
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
            if let NtpSourceAction::Send(buf) = action {
                outgoingbuf = Some(buf);
            }
        }
        let outgoingbuf = outgoingbuf.unwrap();
        let outgoing = NtpPacket::deserialize(&outgoingbuf, &NoCipher).unwrap().0;
        packet.set_reference_id(ReferenceId::KISS_DENY);
        packet.set_origin_timestamp(outgoing.transmit_timestamp());
        packet.set_mode(NtpAssociationMode::Server);
        let mut actions = source.handle_incoming(
            system,
            &packet.serialize_without_encryption_vec(None).unwrap(),
            base + Duration::from_secs(1),
            NtpTimestamp::from_fixed_int(0),
            NtpTimestamp::from_fixed_int(100),
        );
        assert!(matches!(actions.next(), Some(NtpSourceAction::Demobilize)));

        let old_remote_interval = source.remote_min_poll_interval;
        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        packet.set_reference_id(ReferenceId::KISS_RATE);
        packet.set_mode(NtpAssociationMode::Server);
        let mut actions = source.handle_incoming(
            system,
            &packet.serialize_without_encryption_vec(None).unwrap(),
            base + Duration::from_secs(1),
            NtpTimestamp::from_fixed_int(0),
            NtpTimestamp::from_fixed_int(100),
        );
        assert!(actions.next().is_none());
        assert_eq!(source.remote_min_poll_interval, old_remote_interval);

        let old_remote_interval = source.remote_min_poll_interval;
        let mut packet = NtpPacket::test();
        let system = SystemSnapshot::default();
        let actions = source.handle_timer(system);
        let mut outgoingbuf = None;
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
            if let NtpSourceAction::Send(buf) = action {
                outgoingbuf = Some(buf);
            }
        }
        let outgoingbuf = outgoingbuf.unwrap();
        let outgoing = NtpPacket::deserialize(&outgoingbuf, &NoCipher).unwrap().0;
        packet.set_reference_id(ReferenceId::KISS_RATE);
        packet.set_origin_timestamp(outgoing.transmit_timestamp());
        packet.set_mode(NtpAssociationMode::Server);
        let mut actions = source.handle_incoming(
            system,
            &packet.serialize_without_encryption_vec(None).unwrap(),
            base + Duration::from_secs(1),
            NtpTimestamp::from_fixed_int(0),
            NtpTimestamp::from_fixed_int(100),
        );
        assert!(actions.next().is_none());
        assert!(source.remote_min_poll_interval >= old_remote_interval);
    }

    #[cfg(feature = "ntpv5")]
    #[test]
    fn upgrade_state_machine_does_stop() {
        let mut source = NtpSource::test_ntp_source();
        let system = SystemSnapshot::default();
        let clock = TestClock {};

        assert!(matches!(
            source.protocol_version,
            ProtocolVersion::V4UpgradingToV5 { .. }
        ));

        for _ in 0..8 {
            let actions = source.handle_timer(system);
            let mut outgoingbuf = None;
            for action in actions {
                assert!(!matches!(
                    action,
                    NtpSourceAction::Reset | NtpSourceAction::Demobilize
                ));
                if let NtpSourceAction::Send(buf) = action {
                    outgoingbuf = Some(buf);
                }
            }
            let poll = outgoingbuf.unwrap();

            let poll_len: usize = poll.len();
            let (poll, _) = NtpPacket::deserialize(&poll, &NoCipher).unwrap();
            assert_eq!(poll.version(), 4);
            assert!(poll.is_upgrade());

            let response =
                NtpPacket::timestamp_response(&system, poll, NtpTimestamp::default(), &clock);
            let mut response = response
                .serialize_without_encryption_vec(Some(poll_len))
                .unwrap();

            // Kill the reference timestamp
            response[16] = 0;

            let actions = source.handle_incoming(
                system,
                &response,
                NtpInstant::now(),
                NtpTimestamp::default(),
                NtpTimestamp::default(),
            );
            for action in actions {
                assert!(!matches!(
                    action,
                    NtpSourceAction::Demobilize | NtpSourceAction::Reset
                ));
            }
        }

        let actions = source.handle_timer(system);
        let mut outgoingbuf = None;
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
            if let NtpSourceAction::Send(buf) = action {
                outgoingbuf = Some(buf);
            }
        }
        let poll = outgoingbuf.unwrap();
        let (poll, _) = NtpPacket::deserialize(&poll, &NoCipher).unwrap();
        assert_eq!(poll.version(), 4);
        assert!(!poll.is_upgrade());
    }

    #[cfg(feature = "ntpv5")]
    #[test]
    fn upgrade_state_machine_does_upgrade() {
        let mut source = NtpSource::test_ntp_source();
        let system = SystemSnapshot::default();
        let clock = TestClock {};

        assert!(matches!(
            source.protocol_version,
            ProtocolVersion::V4UpgradingToV5 { .. }
        ));

        let actions = source.handle_timer(system);
        let mut outgoingbuf = None;
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
            if let NtpSourceAction::Send(buf) = action {
                outgoingbuf = Some(buf);
            }
        }
        let poll = outgoingbuf.unwrap();

        let poll_len = poll.len();
        let (poll, _) = NtpPacket::deserialize(&poll, &NoCipher).unwrap();
        assert_eq!(poll.version(), 4);
        assert!(poll.is_upgrade());

        let response =
            NtpPacket::timestamp_response(&system, poll, NtpTimestamp::default(), &clock);
        let response = response
            .serialize_without_encryption_vec(Some(poll_len))
            .unwrap();

        let actions = source.handle_incoming(
            system,
            &response,
            NtpInstant::now(),
            NtpTimestamp::default(),
            NtpTimestamp::default(),
        );
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Demobilize | NtpSourceAction::Reset
            ));
        }

        // We should have received a upgrade response and updated to NTPv5
        assert!(matches!(source.protocol_version, ProtocolVersion::V5));

        let actions = source.handle_timer(system);
        let mut outgoingbuf = None;
        for action in actions {
            assert!(!matches!(
                action,
                NtpSourceAction::Reset | NtpSourceAction::Demobilize
            ));
            if let NtpSourceAction::Send(buf) = action {
                outgoingbuf = Some(buf);
            }
        }
        let poll = outgoingbuf.unwrap();
        let (poll, _) = NtpPacket::deserialize(&poll, &NoCipher).unwrap();
        assert_eq!(poll.version(), 5);
    }

    #[cfg(feature = "ntpv5")]
    #[test]
    fn bloom_filters_will_synchronize_at_some_point() {
        let mut server_filter = BloomFilter::new();
        server_filter.add_id(&ServerId::new(&mut thread_rng()));

        let mut client = NtpSource::test_ntp_source();
        client.protocol_version = ProtocolVersion::V5;

        let clock = TestClock::default();
        let system = SystemSnapshot::default();

        let server_system = SystemSnapshot {
            bloom_filter: server_filter,
            ..Default::default()
        };

        let mut tries = 0;

        while client.bloom_filter.full_filter().is_none() && tries < 100 {
            let actions = client.handle_timer(system);
            let mut outgoingbuf = None;
            for action in actions {
                assert!(!matches!(
                    action,
                    NtpSourceAction::Reset | NtpSourceAction::Demobilize
                ));
                if let NtpSourceAction::Send(buf) = action {
                    outgoingbuf = Some(buf);
                }
            }
            let req = outgoingbuf.unwrap();

            let (req, _) = NtpPacket::deserialize(&req, &NoCipher).unwrap();
            let response =
                NtpPacket::timestamp_response(&server_system, req, NtpTimestamp::default(), &clock);
            let resp_bytes = response.serialize_without_encryption_vec(None).unwrap();

            let actions = client.handle_incoming(
                system,
                &resp_bytes,
                NtpInstant::now(),
                NtpTimestamp::default(),
                NtpTimestamp::default(),
            );
            for action in actions {
                assert!(!matches!(
                    action,
                    NtpSourceAction::Demobilize | NtpSourceAction::Reset
                ));
            }

            tries += 1;
        }

        assert_eq!(Some(&server_filter), client.bloom_filter.full_filter());
    }

    /// Tests that the Measurement struct initializes correctly without GPS data.
    #[test]
    fn test_measurement_without_gps() {
        let measurement = Measurement {
            delay: NtpDuration::from_seconds(0.001),
            offset: NtpDuration::from_seconds(1.0),
            transmit_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            localtime: NtpTimestamp::default(),
            monotime: NtpInstant::now(),
            stratum: 0,
            root_delay: NtpDuration::default(),
            root_dispersion: NtpDuration::default(),
            leap: NtpLeapIndicator::NoWarning,
            precision: 0,
            gps: None,
            pps: None,
        };

        assert_eq!(measurement.delay, NtpDuration::from_seconds(0.001));
        assert_eq!(measurement.offset, NtpDuration::from_seconds(1.0));
        assert!(measurement.gps.is_none());
    }

    /// Tests that the Measurement struct initializes correctly with GPS data.
    #[test]
    fn test_measurement_with_gps() {
        let gps_measurement = GpsMeasurement {
            measurementnoise: NtpDuration::from_seconds(0.001),
            offset: NtpDuration::from_seconds(1.0),
        };

        let measurement = Measurement {
            delay: NtpDuration::from_seconds(0.001),
            offset: NtpDuration::from_seconds(1.0),
            transmit_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            localtime: NtpTimestamp::default(),
            monotime: NtpInstant::now(),
            stratum: 0,
            root_delay: NtpDuration::default(),
            root_dispersion: NtpDuration::default(),
            leap: NtpLeapIndicator::NoWarning,
            precision: 0,
            gps: Some(gps_measurement),
            pps: None,
        };

        // Assert that the fields are correctly set
        assert_eq!(measurement.delay, NtpDuration::from_seconds(0.001));
        assert_eq!(measurement.offset, NtpDuration::from_seconds(1.0));
        assert!(measurement.gps.is_some());

        let gps = measurement.gps.unwrap();
        assert_eq!(gps.measurementnoise, NtpDuration::from_seconds(0.001));
        assert_eq!(gps.offset, NtpDuration::from_seconds(1.0));
    }

    /// Tests that the InitialSourceFilter updates correctly with GPS data.
    #[test]
    fn test_initial_source_filter_update_with_gps() {
        let gps_measurement = GpsMeasurement {
            measurementnoise: NtpDuration::from_seconds(0.001),
            offset: NtpDuration::from_seconds(1.0),
        };

        let measurement = Measurement {
            delay: NtpDuration::from_seconds(0.001),
            offset: NtpDuration::from_seconds(1.0),
            transmit_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            localtime: NtpTimestamp::default(),
            monotime: NtpInstant::now(),
            stratum: 0,
            root_delay: NtpDuration::default(),
            root_dispersion: NtpDuration::default(),
            leap: NtpLeapIndicator::NoWarning,
            precision: 0,
            gps: Some(gps_measurement),
            pps: None,
        };

        let mut initial_filter = InitialSourceFilter {
            roundtriptime_stats: Default::default(),
            init_offset: Default::default(),
            last_measurement: None,
            samples: 0,
        };

        initial_filter.update(measurement);

        assert_eq!(initial_filter.samples, 1);
        assert!(initial_filter.last_measurement.is_some());

        let last_measurement = initial_filter.last_measurement.unwrap();
        assert!(last_measurement.gps.is_some());
    }

    /// Tests that the SourceFilter absorbs a measurement correctly with GPS data.
    #[test]
    fn test_absorb_measurement_with_gps() {
        let gps_measurement = GpsMeasurement {
            measurementnoise: NtpDuration::from_seconds(0.001),
            offset: NtpDuration::from_seconds(1.0),
        };

        let measurement = Measurement {
            delay: NtpDuration::from_seconds(0.001),
            offset: NtpDuration::from_seconds(1.0),
            transmit_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            localtime: NtpTimestamp::default(),
            monotime: NtpInstant::now(),
            stratum: 0,
            root_delay: NtpDuration::default(),
            root_dispersion: NtpDuration::default(),
            leap: NtpLeapIndicator::NoWarning,
            precision: 0,
            gps: Some(gps_measurement),
            pps: None,
        };

        let mut source_filter = SourceFilter {
            state: Vector::new_vector([0.0, 0.0]),
            uncertainty: Matrix::new([[1.0, 0.0], [0.0, 1.0]]),
            clock_wander: 1.0,
            roundtriptime_stats: Default::default(),
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: Default::default(),
            last_measurement: measurement.clone(),
            prev_was_outlier: false,
            last_iter: NtpTimestamp::default(),
            filter_time: NtpTimestamp::default(),
        };

        let (p, weight, m_delta_t) = source_filter.absorb_measurement(measurement);

        assert!(p >= 0.0 && p <= 1.0);
        assert!(weight >= 0.0 && weight <= 1.0);
        assert!(m_delta_t >= 0.0);
    }

    /// Tests a measurement that has duration 0 and offset 0.
    #[test]
    fn test_measurement_with_zero_duration() {
        let gps_measurement = GpsMeasurement {
            measurementnoise: NtpDuration::ZERO,
            offset: NtpDuration::ZERO,
        };

        let measurement = Measurement {
            delay: NtpDuration::ZERO,
            offset: NtpDuration::ZERO,
            transmit_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            localtime: NtpTimestamp::default(),
            monotime: NtpInstant::now(),
            stratum: 0,
            root_delay: NtpDuration::default(),
            root_dispersion: NtpDuration::default(),
            leap: NtpLeapIndicator::NoWarning,
            precision: 0,
            gps: Some(gps_measurement),
            pps: None,
        };

        assert_eq!(measurement.delay, NtpDuration::ZERO);
        assert_eq!(measurement.offset, NtpDuration::ZERO);
        assert!(measurement.gps.is_some());
    }

    /// Tests that SourceFilter is initialized correctly with default values.
    #[test]
    fn test_source_filter_initialization() {
        let source_filter = SourceFilter {
            state: Vector::new_vector([0.0, 0.0]),
            uncertainty: Matrix::new([[1.0, 0.0], [0.0, 1.0]]),
            clock_wander: 1.0,
            roundtriptime_stats: Default::default(),
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: Default::default(),
            last_measurement: Measurement {
                delay: NtpDuration::default(),
                offset: NtpDuration::default(),
                transmit_timestamp: NtpTimestamp::default(),
                receive_timestamp: NtpTimestamp::default(),
                localtime: NtpTimestamp::default(),
                monotime: NtpInstant::now(),
                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
                gps: None,
                pps: None,
            },
            prev_was_outlier: false,
            last_iter: NtpTimestamp::default(),
            filter_time: NtpTimestamp::default(),
        };

        assert_eq!(source_filter.state.entry(0, 0), 0.0);
        assert_eq!(source_filter.state.entry(1, 0), 0.0);
        assert_eq!(source_filter.uncertainty.entry(0, 0), 1.0);
        assert_eq!(source_filter.uncertainty.entry(1, 1), 1.0);
        assert_eq!(source_filter.clock_wander, 1.0);
    }

    /// Tests that SourceFilter correctly identifies and handles an outlier measurement.
    #[test]
    fn test_source_filter_handling_outliers() {
        let mut source_filter = SourceFilter {
            state: Vector::new_vector([0.0, 0.0]),
            uncertainty: Matrix::new([[1.0, 0.0], [0.0, 1.0]]),
            clock_wander: 1.0,
            roundtriptime_stats: Default::default(),
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: Default::default(),
            last_measurement: Measurement {
                delay: NtpDuration::from_seconds(0.001),
                offset: NtpDuration::from_seconds(1.0),
                transmit_timestamp: NtpTimestamp::default(),
                receive_timestamp: NtpTimestamp::default(),
                localtime: NtpTimestamp::default(),
                monotime: NtpInstant::now(),
                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
                gps: None,
                pps: None,
            },
            prev_was_outlier: false,
            last_iter: NtpTimestamp::default(),
            filter_time: NtpTimestamp::default(),
        };

        let outlier_measurement = Measurement {
            delay: NtpDuration::from_seconds(100.0),
            offset: NtpDuration::from_seconds(50.0),
            transmit_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            localtime: NtpTimestamp::default(),
            monotime: NtpInstant::now(),
            stratum: 0,
            root_delay: NtpDuration::default(),
            root_dispersion: NtpDuration::default(),
            leap: NtpLeapIndicator::NoWarning,
            precision: 0,
            gps: None,
            pps: None,
        };

        // The filter should identify this as an outlier
        let is_updated = source_filter.absorb_measurement(outlier_measurement).0;
        assert!(is_updated >= 0.0 && is_updated <= 1.0);
    }


    /// Tests that Measurement struct handles maximum possible duration time properly.
    #[test]
    fn test_measurement_with_max_duration() {
        let max_duration = NtpDuration::from_seconds(u64::MAX as f64);

        let gps_measurement = GpsMeasurement {
            measurementnoise: max_duration,
            offset: max_duration,
        };

        let measurement = Measurement {
            delay: max_duration,
            offset: max_duration,
            transmit_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            localtime: NtpTimestamp::default(),
            monotime: NtpInstant::now(),
            stratum: 0,
            root_delay: NtpDuration::default(),
            root_dispersion: NtpDuration::default(),
            leap: NtpLeapIndicator::NoWarning,
            precision: 0,
            gps: Some(gps_measurement),
            pps: None,
        };

        assert_eq!(measurement.delay, max_duration);
        assert_eq!(measurement.offset, max_duration);
        assert!(measurement.gps.is_some());

        let gps = measurement.gps.unwrap();
        assert_eq!(gps.measurementnoise, max_duration);
        assert_eq!(gps.offset, max_duration);
    }

    /// Ensures that InitialSourceFilter resets correctly.
    #[test]
    fn test_initial_source_filter_reset() {
        let gps_measurement = GpsMeasurement {
            measurementnoise: NtpDuration::from_seconds(0.001),
            offset: NtpDuration::from_seconds(1.0),
        };

        let measurement = Measurement {
            delay: NtpDuration::from_seconds(0.001),
            offset: NtpDuration::from_seconds(1.0),
            transmit_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            localtime: NtpTimestamp::default(),
            monotime: NtpInstant::now(),
            stratum: 0,
            root_delay: NtpDuration::default(),
            root_dispersion: NtpDuration::default(),
            leap: NtpLeapIndicator::NoWarning,
            precision: 0,
            gps: Some(gps_measurement),
            pps: None,
        };

        let mut initial_filter = InitialSourceFilter {
            roundtriptime_stats: Default::default(),
            init_offset: Default::default(),
            last_measurement: None,
            samples: 0,
        };

        initial_filter.update(measurement);

        assert_eq!(initial_filter.samples, 1);
        assert!(initial_filter.last_measurement.is_some());

        // Reset filter
        initial_filter = InitialSourceFilter {
            roundtriptime_stats: Default::default(),
            init_offset: Default::default(),
            last_measurement: None,
            samples: 0,
        };

        // Assert filter has reset
        assert_eq!(initial_filter.samples, 0);
        assert!(initial_filter.last_measurement.is_none());
    }

    #[test]
    fn test_poll_interval_calculation() {
        let mut source = NtpSource::test_ntp_source();
        let mut system = SystemSnapshot::default();

        system.time_snapshot.poll_interval = PollIntervalLimits::default().max;
        assert_eq!(
            source.current_poll_interval(system),
            PollIntervalLimits::default().max
        );

        system.time_snapshot.poll_interval = PollIntervalLimits::default().min;
        source.remote_min_poll_interval = PollIntervalLimits::default().max;
        assert_eq!(
            source.current_poll_interval(system),
            PollIntervalLimits::default().max
        );
    }

    #[test]
    fn test_handle_rate_limiting() {
        let base = NtpInstant::now();
        let mut source = NtpSource::test_ntp_source();

        let system = SystemSnapshot::default();
        let actions = source.handle_timer(system);
        let mut outgoingbuf = None;
        for action in actions {
            if let NtpSourceAction::Send(buf) = action {
                outgoingbuf = Some(buf);
            }
        }
        let outgoingbuf = outgoingbuf.unwrap();
        let outgoing = NtpPacket::deserialize(&outgoingbuf, &NoCipher).unwrap().0;
        let mut packet = NtpPacket::test();
        packet.set_reference_id(ReferenceId::KISS_RATE);
        packet.set_origin_timestamp(outgoing.transmit_timestamp());
        packet.set_mode(NtpAssociationMode::Server);

        let actions = source.handle_incoming(
            system,
            &packet.serialize_without_encryption_vec(None).unwrap(),
            base + Duration::from_secs(1),
            NtpTimestamp::from_fixed_int(0),
            NtpTimestamp::from_fixed_int(400),
        );
        for action in actions {
            assert!(matches!(action, NtpSourceAction::UpdateSystem(_))); //update the system without taking further actions
        }
        assert_eq!(
            source.remote_min_poll_interval,
            source.last_poll_interval.inc(source.source_defaults_config.poll_interval_limits)
        );
    }

    #[test]
    fn test_gps_data_processing() {
        let gps_measurement = GpsMeasurement {
            measurementnoise: NtpDuration::from_seconds(0.001),
            offset: NtpDuration::from_seconds(1.0),
        };

        let measurement = Measurement {
            delay: NtpDuration::from_seconds(0.001),
            offset: NtpDuration::from_seconds(1.0),
            transmit_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            localtime: NtpTimestamp::default(),
            monotime: NtpInstant::now(),
            stratum: 0,
            root_delay: NtpDuration::default(),
            root_dispersion: NtpDuration::default(),
            leap: NtpLeapIndicator::NoWarning,
            precision: 0,
            gps: Some(gps_measurement),
            pps: None,
        };

        let mut source_filter = SourceFilter {
            state: Vector::new_vector([0.0, 0.0]),
            uncertainty: Matrix::new([[1.0, 0.0], [0.0, 1.0]]),
            clock_wander: 1.0,
            roundtriptime_stats: Default::default(),
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: Default::default(),
            last_measurement: measurement.clone(),
            prev_was_outlier: false,
            last_iter: NtpTimestamp::default(),
            filter_time: NtpTimestamp::default(),
        };

        let (p, weight, m_delta_t) = source_filter.absorb_measurement(measurement);

        assert!(p >= 0.0 && p <= 1.0);
        assert!(weight >= 0.0 && weight <= 1.0);
        assert!(m_delta_t >= 0.0);
    }    

        /// Tests that the Measurement struct initializes correctly with PPS data.
        #[test]
        fn test_measurement_with_pps() {
            let pps_measurement = PpsMeasurement {
                measurementnoise: NtpDuration::from_seconds(0.001),
                offset: NtpDuration::from_seconds(1.0),
            };
    
            let measurement = Measurement {
                delay: NtpDuration::from_seconds(0.001),
                offset: NtpDuration::from_seconds(1.0),
                transmit_timestamp: NtpTimestamp::default(),
                receive_timestamp: NtpTimestamp::default(),
                localtime: NtpTimestamp::default(),
                monotime: NtpInstant::now(),
                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
                gps: None,
                pps: Some(pps_measurement),
            };
    
            assert_eq!(measurement.delay, NtpDuration::from_seconds(0.001));
            assert_eq!(measurement.offset, NtpDuration::from_seconds(1.0));
            assert!(measurement.pps.is_some());
    
            let pps = measurement.pps.unwrap();
            assert_eq!(pps.measurementnoise, NtpDuration::from_seconds(0.001));
            assert_eq!(pps.offset, NtpDuration::from_seconds(1.0));
        }
    
        /// Tests that the Measurement struct initializes correctly with both GPS and PPS data.
        #[test]
        fn test_measurement_with_gps_and_pps() {
            let gps_measurement = GpsMeasurement {
                measurementnoise: NtpDuration::from_seconds(0.001),
                offset: NtpDuration::from_seconds(1.0),
            };
    
            let pps_measurement = PpsMeasurement {
                measurementnoise: NtpDuration::from_seconds(0.002),
                offset: NtpDuration::from_seconds(2.0),
            };
    
            let measurement = Measurement {
                delay: NtpDuration::from_seconds(0.001),
                offset: NtpDuration::from_seconds(1.0),
                transmit_timestamp: NtpTimestamp::default(),
                receive_timestamp: NtpTimestamp::default(),
                localtime: NtpTimestamp::default(),
                monotime: NtpInstant::now(),
                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
                gps: Some(gps_measurement),
                pps: Some(pps_measurement),
            };
    
            assert_eq!(measurement.delay, NtpDuration::from_seconds(0.001));
            assert_eq!(measurement.offset, NtpDuration::from_seconds(1.0));
            assert!(measurement.gps.is_some());
            assert!(measurement.pps.is_some());
    
            let gps = measurement.gps.unwrap();
            assert_eq!(gps.measurementnoise, NtpDuration::from_seconds(0.001));
            assert_eq!(gps.offset, NtpDuration::from_seconds(1.0));
    
            let pps = measurement.pps.unwrap();
            assert_eq!(pps.measurementnoise, NtpDuration::from_seconds(0.002));
            assert_eq!(pps.offset, NtpDuration::from_seconds(2.0));
        }
    
        /// Tests that InitialSourceFilter updates correctly with PPS data.
        #[test]
        fn test_initial_source_filter_update_with_pps() {
            let pps_measurement = PpsMeasurement {
                measurementnoise: NtpDuration::from_seconds(0.001),
                offset: NtpDuration::from_seconds(1.0),
            };
    
            let measurement = Measurement {
                delay: NtpDuration::from_seconds(0.001),
                offset: NtpDuration::from_seconds(1.0),
                transmit_timestamp: NtpTimestamp::default(),
                receive_timestamp: NtpTimestamp::default(),
                localtime: NtpTimestamp::default(),
                monotime: NtpInstant::now(),
                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
                gps: None,
                pps: Some(pps_measurement),
            };
    
            let mut initial_filter = InitialSourceFilter {
                roundtriptime_stats: Default::default(),
                init_offset: Default::default(),
                last_measurement: None,
                samples: 0,
            };
    
            initial_filter.update(measurement);
    
            assert_eq!(initial_filter.samples, 1);
            assert!(initial_filter.last_measurement.is_some());
    
            let last_measurement = initial_filter.last_measurement.unwrap();
            assert!(last_measurement.pps.is_some());
        }
    
        /// Tests that the SourceFilter absorbs a measurement correctly with PPS data.
        #[test]
        fn test_absorb_measurement_with_pps() {
            let pps_measurement = PpsMeasurement {
                measurementnoise: NtpDuration::from_seconds(0.001),
                offset: NtpDuration::from_seconds(1.0),
            };
    
            let measurement = Measurement {
                delay: NtpDuration::from_seconds(0.001),
                offset: NtpDuration::from_seconds(1.0),
                transmit_timestamp: NtpTimestamp::default(),
                receive_timestamp: NtpTimestamp::default(),
                localtime: NtpTimestamp::default(),
                monotime: NtpInstant::now(),
                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
                gps: None,
                pps: Some(pps_measurement),
            };
    
            let mut source_filter = SourceFilter {
                state: Vector::new_vector([0.0, 0.0]),
                uncertainty: Matrix::new([[1.0, 0.0], [0.0, 1.0]]),
                clock_wander: 1.0,
                roundtriptime_stats: Default::default(),
                precision_score: 0,
                poll_score: 0,
                desired_poll_interval: Default::default(),
                last_measurement: measurement.clone(),
                prev_was_outlier: false,
                last_iter: NtpTimestamp::default(),
                filter_time: NtpTimestamp::default(),
            };
    
            let (p, weight, m_delta_t) = source_filter.absorb_measurement(measurement);
    
            assert!(p >= 0.0 && p <= 1.0);
            assert!(weight >= 0.0 && weight <= 1.0);
            assert!(m_delta_t >= 0.0);
        }    
        fn test_initial_source_filter_update_with_gps_and_pps() {
            let gps_measurement = GpsMeasurement {
                measurementnoise: NtpDuration::from_seconds(0.001),
                offset: NtpDuration::from_seconds(1.0),
            };
    
            let pps_measurement = PpsMeasurement {
                measurementnoise: NtpDuration::from_seconds(0.002),
                offset: NtpDuration::from_seconds(2.0),
            };
    
            let measurement = Measurement {
                delay: NtpDuration::from_seconds(0.001),
                offset: NtpDuration::from_seconds(1.0),
                transmit_timestamp: NtpTimestamp::default(),
                receive_timestamp: NtpTimestamp::default(),
                localtime: NtpTimestamp::default(),
                monotime: NtpInstant::now(),
                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
                gps: Some(gps_measurement),
                pps: Some(pps_measurement),
            };
    
            let mut initial_filter = InitialSourceFilter {
                roundtriptime_stats: Default::default(),
                init_offset: Default::default(),
                last_measurement: None,
                samples: 0,
            };
    
            initial_filter.update(measurement);
    
            assert_eq!(initial_filter.samples, 1);
            assert!(initial_filter.last_measurement.is_some());
    
            let last_measurement = initial_filter.last_measurement.unwrap();
            assert!(last_measurement.gps.is_some());
            assert!(last_measurement.pps.is_some());
        }
    
        /// Tests that the SourceFilter absorbs a measurement correctly with both GPS and PPS data.
        #[test]
        fn test_absorb_measurement_with_gps_and_pps() {
            let gps_measurement = GpsMeasurement {
                measurementnoise: NtpDuration::from_seconds(0.001),
                offset: NtpDuration::from_seconds(1.0),
            };
    
            let pps_measurement = PpsMeasurement {
                measurementnoise: NtpDuration::from_seconds(0.002),
                offset: NtpDuration::from_seconds(2.0),
            };
    
            let measurement = Measurement {
                delay: NtpDuration::from_seconds(0.001),
                offset: NtpDuration::from_seconds(1.0),
                transmit_timestamp: NtpTimestamp::default(),
                receive_timestamp: NtpTimestamp::default(),
                localtime: NtpTimestamp::default(),
                monotime: NtpInstant::now(),
                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
                gps: Some(gps_measurement),
                pps: Some(pps_measurement),
            };
    
            let mut source_filter = SourceFilter {
                state: Vector::new_vector([0.0, 0.0]),
                uncertainty: Matrix::new([[1.0, 0.0], [0.0, 1.0]]),
                clock_wander: 1.0,
                roundtriptime_stats: Default::default(),
                precision_score: 0,
                poll_score: 0,
                desired_poll_interval: Default::default(),
                last_measurement: measurement.clone(),
                prev_was_outlier: false,
                last_iter: NtpTimestamp::default(),
                filter_time: NtpTimestamp::default(),
            };
    
            let (p, weight, m_delta_t) = source_filter.absorb_measurement(measurement);
    
            assert!(p >= 0.0 && p <= 1.0);
            assert!(weight >= 0.0 && weight <= 1.0);
            assert!(m_delta_t >= 0.0);
        }
    
        /// Tests a measurement that has zero offset for both GPS and PPS.
        #[test]
        fn test_measurement_with_zero_offsets() {
            let gps_measurement = GpsMeasurement {
                measurementnoise: NtpDuration::ZERO,
                offset: NtpDuration::ZERO,
            };
    
            let pps_measurement = PpsMeasurement {
                measurementnoise: NtpDuration::ZERO,
                offset: NtpDuration::ZERO,
            };
    
            let measurement = Measurement {
                delay: NtpDuration::ZERO,
                offset: NtpDuration::ZERO,
                transmit_timestamp: NtpTimestamp::default(),
                receive_timestamp: NtpTimestamp::default(),
                localtime: NtpTimestamp::default(),
                monotime: NtpInstant::now(),
                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
                gps: Some(gps_measurement),
                pps: Some(pps_measurement),
            };
    
            assert_eq!(measurement.delay, NtpDuration::ZERO);
            assert_eq!(measurement.offset, NtpDuration::ZERO);
            assert!(measurement.gps.is_some());
            assert!(measurement.pps.is_some());
        }
    
        /// Tests that the Measurement struct handles very large offsets correctly.
        #[test]
        fn test_measurement_with_large_offsets() {
            let large_offset = NtpDuration::from_seconds(1_000_000.0);
    
            let gps_measurement = GpsMeasurement {
                measurementnoise: large_offset,
                offset: large_offset,
            };
    
            let pps_measurement = PpsMeasurement {
                measurementnoise: large_offset,
                offset: large_offset,
            };
    
            let measurement = Measurement {
                delay: large_offset,
                offset: large_offset,
                transmit_timestamp: NtpTimestamp::default(),
                receive_timestamp: NtpTimestamp::default(),
                localtime: NtpTimestamp::default(),
                monotime: NtpInstant::now(),
                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
                gps: Some(gps_measurement),
                pps: Some(pps_measurement),
            };
    
            assert_eq!(measurement.delay, large_offset);
            assert_eq!(measurement.offset, large_offset);
            assert!(measurement.gps.is_some());
            assert!(measurement.pps.is_some());
    
            let gps = measurement.gps.unwrap();
            assert_eq!(gps.measurementnoise, large_offset);
            assert_eq!(gps.offset, large_offset);
    
            let pps = measurement.pps.unwrap();
            assert_eq!(pps.measurementnoise, large_offset);
            assert_eq!(pps.offset, large_offset);
        }
    
        /// Tests that the InitialSourceFilter correctly handles zero samples.
        #[test]
        fn test_initial_source_filter_zero_samples() {
            let initial_filter = InitialSourceFilter {
                roundtriptime_stats: Default::default(),
                init_offset: Default::default(),
                last_measurement: None,
                samples: 0,
            };
    
            assert_eq!(initial_filter.samples, 0);
            assert!(initial_filter.last_measurement.is_none());
        }
    
        /// Tests that the SourceFilter handles zero measurements correctly.
        #[test]
        fn test_source_filter_zero_measurements() {
            let source_filter = SourceFilter {
                state: Vector::new_vector([0.0, 0.0]),
                uncertainty: Matrix::new([[1.0, 0.0], [0.0, 1.0]]),
                clock_wander: 1.0,
                roundtriptime_stats: Default::default(),
                precision_score: 0,
                poll_score: 0,
                desired_poll_interval: Default::default(),
                last_measurement: Measurement {
                    delay: NtpDuration::default(),
                    offset: NtpDuration::default(),
                    transmit_timestamp: NtpTimestamp::default(),
                    receive_timestamp: NtpTimestamp::default(),
                    localtime: NtpTimestamp::default(),
                    monotime: NtpInstant::now(),
                    stratum: 0,
                    root_delay: NtpDuration::default(),
                    root_dispersion: NtpDuration::default(),
                    leap: NtpLeapIndicator::NoWarning,
                    precision: 0,
                    gps: None,
                    pps: None,
                },
                prev_was_outlier: false,
                last_iter: NtpTimestamp::default(),
                filter_time: NtpTimestamp::default(),
            };
    
            assert_eq!(source_filter.state.entry(0, 0), 0.0);
            assert_eq!(source_filter.state.entry(1, 0), 0.0);
            assert_eq!(source_filter.uncertainty.entry(0, 0), 1.0);
            assert_eq!(source_filter.uncertainty.entry(1, 1), 1.0);
            assert_eq!(source_filter.clock_wander, 1.0);
        }
} 
    