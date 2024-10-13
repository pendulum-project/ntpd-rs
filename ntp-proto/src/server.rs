use std::{
    collections::hash_map::RandomState,
    fmt::Display,
    io::Cursor,
    net::{AddrParseError, IpAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use serde::{de, Deserialize, Deserializer};

use crate::{
    ipfilter::IpFilter, KeySet, NoCipher, NtpClock, NtpPacket, NtpTimestamp, PacketParsingError,
    SystemSnapshot,
};

pub enum ServerAction<'a> {
    Ignore,
    Respond { message: &'a [u8] },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServerReason {
    /// Rate limit mechanism kicked in
    RateLimit,
    /// Packet could not be parsed because it was malformed in some way
    ParseError,
    /// Packet could be parsed but the cryptography was invalid
    InvalidCrypto,
    /// Internal error in the server
    InternalError,
    /// Configuration was used to decide response
    Policy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServerResponse {
    /// NTS was invalid (failure to decrypt etc)
    NTSNak,
    /// Sent a deny response to client
    Deny,
    /// Only for a conscious choice to not respond, error conditions are separate
    Ignore,
    /// Accepted packet and provided time to requestor
    ProvideTime,
}

pub trait ServerStatHandler {
    /// Called by the server handle once per packet
    fn register(&mut self, version: u8, nts: bool, reason: ServerReason, response: ServerResponse);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterAction {
    Ignore,
    Deny,
}

impl From<FilterAction> for ServerResponse {
    fn from(value: FilterAction) -> Self {
        match value {
            FilterAction::Ignore => ServerResponse::Ignore,
            FilterAction::Deny => ServerResponse::Deny,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Deserialize)]
pub struct FilterList {
    pub filter: Vec<IpSubnet>,
    pub action: FilterAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerConfig {
    pub denylist: FilterList,
    pub allowlist: FilterList,
    pub rate_limiting_cache_size: usize,
    pub rate_limiting_cutoff: Duration,
    pub require_nts: Option<FilterAction>,
}

pub struct Server<C> {
    config: ServerConfig,
    clock: C,
    denyfilter: IpFilter,
    allowfilter: IpFilter,
    client_cache: TimestampedCache<IpAddr>,
    system: SystemSnapshot,
    keyset: Arc<KeySet>,
}

// Quick estimation of ntp packet message version without doing full parsing
fn fallback_message_version(message: &[u8]) -> u8 {
    message.first().map_or(0, |v| (v & 0b0011_1000) >> 3)
}

impl<C> Server<C> {
    /// Create a new server
    pub fn new(
        config: ServerConfig,
        clock: C,
        system: SystemSnapshot,
        keyset: Arc<KeySet>,
    ) -> Self {
        let denyfilter = IpFilter::new(&config.denylist.filter);
        let allowfilter = IpFilter::new(&config.allowlist.filter);
        let client_cache = TimestampedCache::new(config.rate_limiting_cache_size);
        Self {
            config,
            clock,
            denyfilter,
            allowfilter,
            client_cache,
            system,
            keyset,
        }
    }

    /// Update the [`ServerConfig`] of the server
    pub fn update_config(&mut self, config: ServerConfig) {
        if self.config.denylist.filter != config.denylist.filter {
            self.denyfilter = IpFilter::new(&config.denylist.filter);
        }
        if self.config.allowlist.filter != config.allowlist.filter {
            self.allowfilter = IpFilter::new(&config.allowlist.filter);
        }
        if self.config.rate_limiting_cache_size != config.rate_limiting_cache_size {
            self.client_cache = TimestampedCache::new(config.rate_limiting_cache_size);
        }
        self.config = config;
    }

    /// Provide the server with the latest [`SystemSnapshot`]
    pub fn update_system(&mut self, system: SystemSnapshot) {
        self.system = system;
    }

    /// Provide the server with a new [`KeySet`]
    pub fn update_keyset(&mut self, keyset: Arc<KeySet>) {
        self.keyset = keyset;
    }

    fn intended_action(&mut self, client_ip: IpAddr) -> (ServerResponse, ServerReason) {
        if self.denyfilter.is_in(&client_ip) {
            // First apply denylist
            (self.config.denylist.action.into(), ServerReason::Policy)
        } else if !self.allowfilter.is_in(&client_ip) {
            // Then allowlist
            (self.config.allowlist.action.into(), ServerReason::Policy)
        } else if !self.client_cache.is_allowed(
            client_ip,
            Instant::now(),
            self.config.rate_limiting_cutoff,
        ) {
            // Then ratelimit
            (ServerResponse::Ignore, ServerReason::RateLimit)
        } else {
            // Then accept
            (ServerResponse::ProvideTime, ServerReason::Policy)
        }
    }
}

impl<C: NtpClock> Server<C> {
    /// Handle a packet sent to the server
    ///
    /// If the buffer isn't large enough to encode the reply, this
    /// will log an error and ignore the incoming packet. A buffer
    /// as large as the message will always suffice.
    #[allow(clippy::cast_possible_truncation)]
    pub fn handle<'a>(
        &mut self,
        client_ip: IpAddr,
        recv_timestamp: NtpTimestamp,
        message: &[u8],
        buffer: &'a mut [u8],
        stats_handler: &mut impl ServerStatHandler,
    ) -> ServerAction<'a> {
        let (mut action, mut reason) = self.intended_action(client_ip);

        if action == ServerResponse::Ignore {
            // Early exit for ignore
            stats_handler.register(fallback_message_version(message), false, reason, action);
            return ServerAction::Ignore;
        }

        // Try and parse the message
        let (packet, cookie) = match NtpPacket::deserialize(message, self.keyset.as_ref()) {
            Ok(packet) => packet,
            Err(PacketParsingError::DecryptError(packet)) => {
                // Don't care about decryption errors when denying anyway
                if action != ServerResponse::Deny {
                    action = ServerResponse::NTSNak;
                    reason = ServerReason::InvalidCrypto;
                }
                (packet, None)
            }
            Err(_) => {
                stats_handler.register(
                    fallback_message_version(message),
                    false,
                    ServerReason::ParseError,
                    ServerResponse::Ignore,
                );
                return ServerAction::Ignore;
            }
        };

        // Generate the appropriate response
        let version = packet.version();
        let nts = cookie.is_some() || action == ServerResponse::NTSNak;

        // ignore non-NTS packets when configured to require NTS
        if let (false, Some(non_nts_action)) = (nts, self.config.require_nts) {
            if non_nts_action == FilterAction::Ignore {
                stats_handler.register(version, nts, ServerReason::Policy, ServerResponse::Ignore);
                return ServerAction::Ignore;
            } else {
                action = ServerResponse::Deny;
                reason = ServerReason::Policy;
            }
        }

        let mut cursor = Cursor::new(buffer);
        let result = match action {
            ServerResponse::NTSNak => {
                NtpPacket::nts_nak_response(packet).serialize(&mut cursor, &NoCipher, None)
            }
            ServerResponse::Deny => {
                if let Some(cookie) = cookie {
                    NtpPacket::nts_deny_response(packet).serialize(
                        &mut cursor,
                        cookie.s2c.as_ref(),
                        None,
                    )
                } else {
                    NtpPacket::deny_response(packet).serialize(&mut cursor, &NoCipher, None)
                }
            }
            ServerResponse::ProvideTime => {
                if let Some(cookie) = cookie {
                    NtpPacket::nts_timestamp_response(
                        &self.system,
                        packet,
                        recv_timestamp,
                        &self.clock,
                        &cookie,
                        &self.keyset,
                    )
                    .serialize(
                        &mut cursor,
                        cookie.s2c.as_ref(),
                        Some(message.len()),
                    )
                } else {
                    NtpPacket::timestamp_response(&self.system, packet, recv_timestamp, &self.clock)
                        .serialize(&mut cursor, &NoCipher, Some(message.len()))
                }
            }
            ServerResponse::Ignore => unreachable!(),
        };
        match result {
            Ok(()) => {
                stats_handler.register(version, nts, reason, action);
                let length = cursor.position();
                ServerAction::Respond {
                    message: &cursor.into_inner()[..length as _],
                }
            }
            Err(e) => {
                tracing::error!("Could not serialize response: {}", e);
                stats_handler.register(
                    version,
                    nts,
                    ServerReason::InternalError,
                    ServerResponse::Ignore,
                );
                ServerAction::Ignore
            }
        }
    }
}

/// A size-bounded cache where each entry is timestamped.
///
/// The planned use is in rate limiting: we keep track of when a source last checked in. If it checks
/// in too often, we issue a rate limiting KISS code.
///
/// For this use case we want fast
///
/// - lookups: for each incoming IP we must check when it last checked in
/// - inserts: for each incoming IP we store that its most recent check-in is now
///
/// Hence, this data structure is a vector, and we use a simple hash function to turn the incoming
/// address into an index. Lookups and inserts are therefore O(1).
///
/// The likelihood of hash collisions can be controlled by changing the size of the cache. Hash collisions
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

    #[allow(clippy::cast_possible_truncation)]
    fn index(&self, item: &T) -> usize {
        use std::hash::{BuildHasher, Hasher};

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpSubnet {
    pub addr: IpAddr,
    pub mask: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubnetParseError {
    Subnet,
    Ip(AddrParseError),
    Mask,
}

impl std::error::Error for SubnetParseError {}

impl Display for SubnetParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Subnet => write!(f, "Invalid subnet syntax"),
            Self::Ip(e) => write!(f, "{e} in subnet"),
            Self::Mask => write!(f, "Invalid subnet mask"),
        }
    }
}

impl From<AddrParseError> for SubnetParseError {
    fn from(value: AddrParseError) -> Self {
        Self::Ip(value)
    }
}

impl std::str::FromStr for IpSubnet {
    type Err = SubnetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, mask) = s.split_once('/').ok_or(SubnetParseError::Subnet)?;
        let addr: IpAddr = addr.parse()?;
        let mask: u8 = mask.parse().map_err(|_| SubnetParseError::Mask)?;
        let max_mask = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if mask > max_mask {
            return Err(SubnetParseError::Mask);
        }
        Ok(IpSubnet { addr, mask })
    }
}

impl<'de> Deserialize<'de> for IpSubnet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        std::str::FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use serde_test::{assert_de_tokens, assert_de_tokens_error, Token};

    use crate::{
        nts_record::AeadAlgorithm, packet::AesSivCmac256, Cipher, DecodedServerCookie,
        KeySetProvider, NtpDuration, NtpLeapIndicator, PollIntervalLimits,
    };

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct TestClock {
        cur: NtpTimestamp,
    }

    impl NtpClock for TestClock {
        type Error = std::time::SystemTimeError;

        fn now(&self) -> std::result::Result<NtpTimestamp, Self::Error> {
            Ok(self.cur)
        }

        fn set_frequency(&self, _freq: f64) -> Result<NtpTimestamp, Self::Error> {
            panic!("Shouldn't be called by server");
        }

        fn get_frequency(&self) -> Result<f64, Self::Error> {
            Ok(0.0)
        }

        fn step_clock(&self, _offset: NtpDuration) -> Result<NtpTimestamp, Self::Error> {
            panic!("Shouldn't be called by server");
        }

        fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by server");
        }

        fn error_estimate_update(
            &self,
            _est_error: NtpDuration,
            _max_error: NtpDuration,
        ) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by server");
        }

        fn status_update(&self, _leap_status: NtpLeapIndicator) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by source");
        }
    }

    #[derive(Debug, Default)]
    struct TestStatHandler {
        last_register: Option<(u8, bool, ServerReason, ServerResponse)>,
    }

    impl ServerStatHandler for TestStatHandler {
        fn register(
            &mut self,
            version: u8,
            nts: bool,
            reason: ServerReason,
            response: ServerResponse,
        ) {
            assert!(self.last_register.is_none());
            self.last_register = Some((version, nts, reason, response));
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn serialize_packet_unencrypted(send_packet: &NtpPacket) -> Vec<u8> {
        let mut buf = vec![0; 1024];
        let mut cursor = Cursor::new(buf.as_mut_slice());
        send_packet.serialize(&mut cursor, &NoCipher, None).unwrap();

        let end = cursor.position() as usize;
        buf.truncate(end);
        buf
    }

    #[allow(clippy::cast_possible_truncation)]
    fn serialize_packet_encrypted(send_packet: &NtpPacket, key: &dyn Cipher) -> Vec<u8> {
        let mut buf = vec![0; 1024];
        let mut cursor = Cursor::new(buf.as_mut_slice());
        send_packet.serialize(&mut cursor, key, None).unwrap();

        let end = cursor.position() as usize;
        buf.truncate(end);
        buf
    }

    #[test]
    fn test_server_allow_filter() {
        let config = ServerConfig {
            denylist: FilterList {
                filter: vec![],
                action: FilterAction::Deny,
            },
            allowlist: FilterList {
                filter: vec!["127.0.0.0/24".parse().unwrap()],
                action: FilterAction::Ignore,
            },
            rate_limiting_cutoff: Duration::from_secs(1),
            rate_limiting_cache_size: 0,
            require_nts: None,
        };
        let clock = TestClock {
            cur: NtpTimestamp::from_fixed_int(200),
        };
        let mut stats = TestStatHandler::default();

        let mut server = Server::new(
            config,
            clock,
            SystemSnapshot::default(),
            KeySetProvider::new(1).get(),
        );

        let (packet, id) = NtpPacket::poll_message(PollIntervalLimits::default().min);
        let serialized = serialize_packet_unencrypted(&packet);

        let mut buf = [0; 48];
        let response = server.handle(
            "127.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((4, false, ServerReason::Policy, ServerResponse::ProvideTime))
        );
        let data = match response {
            ServerAction::Ignore => panic!("Server ignored packet"),
            ServerAction::Respond { message } => message,
        };
        let packet = NtpPacket::deserialize(data, &NoCipher).unwrap().0;
        assert_ne!(packet.stratum(), 0);
        assert!(packet.valid_server_response(id, false));
        assert_eq!(
            packet.receive_timestamp(),
            NtpTimestamp::from_fixed_int(100)
        );
        assert_eq!(
            packet.transmit_timestamp(),
            NtpTimestamp::from_fixed_int(200)
        );

        let mut buf = [0; 48];
        let response = server.handle(
            "128.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((4, false, ServerReason::Policy, ServerResponse::Ignore))
        );
        assert!(matches!(response, ServerAction::Ignore));

        let config = ServerConfig {
            denylist: FilterList {
                filter: vec![],
                action: FilterAction::Deny,
            },
            allowlist: FilterList {
                filter: vec!["127.0.0.0/24".parse().unwrap()],
                action: FilterAction::Deny,
            },
            rate_limiting_cutoff: Duration::from_secs(1),
            rate_limiting_cache_size: 0,
            require_nts: None,
        };
        server.update_config(config);

        let mut buf = [0; 48];
        let response = server.handle(
            "128.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((4, false, ServerReason::Policy, ServerResponse::Deny))
        );
        let data = match response {
            ServerAction::Ignore => panic!("Server ignored packet"),
            ServerAction::Respond { message } => message,
        };
        let packet = NtpPacket::deserialize(data, &NoCipher).unwrap().0;
        assert!(packet.valid_server_response(id, false));
        assert!(packet.is_kiss_deny());
    }

    #[test]
    fn test_server_deny_filter() {
        let config = ServerConfig {
            denylist: FilterList {
                filter: vec!["128.0.0.0/24".parse().unwrap()],
                action: FilterAction::Deny,
            },
            allowlist: FilterList {
                filter: vec!["0.0.0.0/0".parse().unwrap()],
                action: FilterAction::Ignore,
            },
            rate_limiting_cutoff: Duration::from_secs(1),
            rate_limiting_cache_size: 0,
            require_nts: None,
        };
        let clock = TestClock {
            cur: NtpTimestamp::from_fixed_int(200),
        };
        let mut stats = TestStatHandler::default();

        let mut server = Server::new(
            config,
            clock,
            SystemSnapshot::default(),
            KeySetProvider::new(1).get(),
        );

        let (packet, id) = NtpPacket::poll_message(PollIntervalLimits::default().min);
        let serialized = serialize_packet_unencrypted(&packet);

        let mut buf = [0; 48];
        let response = server.handle(
            "127.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((4, false, ServerReason::Policy, ServerResponse::ProvideTime))
        );
        let data = match response {
            ServerAction::Ignore => panic!("Server ignored packet"),
            ServerAction::Respond { message } => message,
        };
        let packet = NtpPacket::deserialize(data, &NoCipher).unwrap().0;
        assert_ne!(packet.stratum(), 0);
        assert!(packet.valid_server_response(id, false));
        assert_eq!(
            packet.receive_timestamp(),
            NtpTimestamp::from_fixed_int(100)
        );
        assert_eq!(
            packet.transmit_timestamp(),
            NtpTimestamp::from_fixed_int(200)
        );

        let mut buf = [0; 48];
        let response = server.handle(
            "128.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((4, false, ServerReason::Policy, ServerResponse::Deny))
        );
        let data = match response {
            ServerAction::Ignore => panic!("Server ignored packet"),
            ServerAction::Respond { message } => message,
        };
        let packet = NtpPacket::deserialize(data, &NoCipher).unwrap().0;
        assert!(packet.valid_server_response(id, false));
        assert!(packet.is_kiss_deny());

        let config = ServerConfig {
            denylist: FilterList {
                filter: vec!["128.0.0.0/24".parse().unwrap()],
                action: FilterAction::Ignore,
            },
            allowlist: FilterList {
                filter: vec!["0.0.0.0/0".parse().unwrap()],
                action: FilterAction::Ignore,
            },
            rate_limiting_cutoff: Duration::from_secs(1),
            rate_limiting_cache_size: 0,
            require_nts: None,
        };
        server.update_config(config);

        let mut buf = [0; 48];
        let response = server.handle(
            "128.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((4, false, ServerReason::Policy, ServerResponse::Ignore))
        );
        assert!(matches!(response, ServerAction::Ignore));
    }

    #[test]
    fn test_server_rate_limit() {
        let config = ServerConfig {
            denylist: FilterList {
                filter: vec![],
                action: FilterAction::Deny,
            },
            allowlist: FilterList {
                filter: vec!["0.0.0.0/0".parse().unwrap()],
                action: FilterAction::Ignore,
            },
            rate_limiting_cutoff: Duration::from_millis(100),
            rate_limiting_cache_size: 32,
            require_nts: None,
        };
        let clock = TestClock {
            cur: NtpTimestamp::from_fixed_int(200),
        };
        let mut stats = TestStatHandler::default();

        let mut server = Server::new(
            config,
            clock,
            SystemSnapshot::default(),
            KeySetProvider::new(1).get(),
        );

        let (packet, id) = NtpPacket::poll_message(PollIntervalLimits::default().min);
        let serialized = serialize_packet_unencrypted(&packet);

        let mut buf = [0; 48];
        let response = server.handle(
            "127.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((4, false, ServerReason::Policy, ServerResponse::ProvideTime))
        );
        let data = match response {
            ServerAction::Ignore => panic!("Server ignored packet"),
            ServerAction::Respond { message } => message,
        };
        let packet = NtpPacket::deserialize(data, &NoCipher).unwrap().0;
        assert_ne!(packet.stratum(), 0);
        assert!(packet.valid_server_response(id, false));
        assert_eq!(
            packet.receive_timestamp(),
            NtpTimestamp::from_fixed_int(100)
        );
        assert_eq!(
            packet.transmit_timestamp(),
            NtpTimestamp::from_fixed_int(200)
        );

        let mut buf = [0; 48];
        let response = server.handle(
            "127.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((4, false, ServerReason::RateLimit, ServerResponse::Ignore))
        );
        assert!(matches!(response, ServerAction::Ignore));

        std::thread::sleep(std::time::Duration::from_millis(120));

        let mut buf = [0; 48];
        let response = server.handle(
            "127.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((4, false, ServerReason::Policy, ServerResponse::ProvideTime))
        );
        let data = match response {
            ServerAction::Ignore => panic!("Server ignored packet"),
            ServerAction::Respond { message } => message,
        };
        let packet = NtpPacket::deserialize(data, &NoCipher).unwrap().0;
        assert_ne!(packet.stratum(), 0);
        assert!(packet.valid_server_response(id, false));
        assert_eq!(
            packet.receive_timestamp(),
            NtpTimestamp::from_fixed_int(100)
        );
        assert_eq!(
            packet.transmit_timestamp(),
            NtpTimestamp::from_fixed_int(200)
        );

        let config = ServerConfig {
            denylist: FilterList {
                filter: vec![],
                action: FilterAction::Deny,
            },
            allowlist: FilterList {
                filter: vec!["0.0.0.0/0".parse().unwrap()],
                action: FilterAction::Ignore,
            },
            rate_limiting_cutoff: Duration::from_millis(100),
            rate_limiting_cache_size: 0,
            require_nts: None,
        };

        server.update_config(config);

        let mut buf = [0; 48];
        let response = server.handle(
            "127.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((4, false, ServerReason::Policy, ServerResponse::ProvideTime))
        );
        let data = match response {
            ServerAction::Ignore => panic!("Server ignored packet"),
            ServerAction::Respond { message } => message,
        };
        let packet = NtpPacket::deserialize(data, &NoCipher).unwrap().0;
        assert_ne!(packet.stratum(), 0);
        assert!(packet.valid_server_response(id, false));
        assert_eq!(
            packet.receive_timestamp(),
            NtpTimestamp::from_fixed_int(100)
        );
        assert_eq!(
            packet.transmit_timestamp(),
            NtpTimestamp::from_fixed_int(200)
        );

        let mut buf = [0; 48];
        let response = server.handle(
            "127.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((4, false, ServerReason::Policy, ServerResponse::ProvideTime))
        );
        let data = match response {
            ServerAction::Ignore => panic!("Server ignored packet"),
            ServerAction::Respond { message } => message,
        };
        let packet = NtpPacket::deserialize(data, &NoCipher).unwrap().0;
        assert_ne!(packet.stratum(), 0);
        assert!(packet.valid_server_response(id, false));
        assert_eq!(
            packet.receive_timestamp(),
            NtpTimestamp::from_fixed_int(100)
        );
        assert_eq!(
            packet.transmit_timestamp(),
            NtpTimestamp::from_fixed_int(200)
        );
    }

    #[test]
    fn test_server_corrupted() {
        let config = ServerConfig {
            denylist: FilterList {
                filter: vec![],
                action: FilterAction::Deny,
            },
            allowlist: FilterList {
                filter: vec!["0.0.0.0/0".parse().unwrap()],
                action: FilterAction::Ignore,
            },
            rate_limiting_cutoff: Duration::from_millis(100),
            rate_limiting_cache_size: 0,
            require_nts: None,
        };
        let clock = TestClock {
            cur: NtpTimestamp::from_fixed_int(200),
        };
        let mut stats = TestStatHandler::default();

        let mut server = Server::new(
            config,
            clock,
            SystemSnapshot::default(),
            KeySetProvider::new(1).get(),
        );

        let (packet, _) = NtpPacket::poll_message(PollIntervalLimits::default().min);
        let mut serialized = serialize_packet_unencrypted(&packet);

        let mut buf = [0; 1];
        let response = server.handle(
            "127.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((
                4,
                false,
                ServerReason::InternalError,
                ServerResponse::Ignore
            ))
        );
        assert!(matches!(response, ServerAction::Ignore));

        serialized[0] = 42;

        let mut buf = [0; 48];
        let response = server.handle(
            "127.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((5, false, ServerReason::ParseError, ServerResponse::Ignore))
        );
        assert!(matches!(response, ServerAction::Ignore));

        let config = ServerConfig {
            denylist: FilterList {
                filter: vec![],
                action: FilterAction::Deny,
            },
            allowlist: FilterList {
                filter: vec!["128.0.0.0/24".parse().unwrap()],
                action: FilterAction::Deny,
            },
            rate_limiting_cutoff: Duration::from_millis(100),
            rate_limiting_cache_size: 0,
            require_nts: None,
        };
        server.update_config(config);

        let mut buf = [0; 48];
        let response = server.handle(
            "127.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((5, false, ServerReason::ParseError, ServerResponse::Ignore))
        );
        assert!(matches!(response, ServerAction::Ignore));

        let config = ServerConfig {
            denylist: FilterList {
                filter: vec![],
                action: FilterAction::Deny,
            },
            allowlist: FilterList {
                filter: vec!["128.0.0.0/24".parse().unwrap()],
                action: FilterAction::Ignore,
            },
            rate_limiting_cutoff: Duration::from_millis(100),
            rate_limiting_cache_size: 0,
            require_nts: None,
        };
        server.update_config(config);

        let mut buf = [0; 48];
        let response = server.handle(
            "127.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((5, false, ServerReason::Policy, ServerResponse::Ignore))
        );
        assert!(matches!(response, ServerAction::Ignore));

        let config = ServerConfig {
            denylist: FilterList {
                filter: vec!["127.0.0.0/24".parse().unwrap()],
                action: FilterAction::Deny,
            },
            allowlist: FilterList {
                filter: vec!["0.0.0.0/0".parse().unwrap()],
                action: FilterAction::Ignore,
            },
            rate_limiting_cutoff: Duration::from_millis(100),
            rate_limiting_cache_size: 0,
            require_nts: None,
        };
        server.update_config(config);

        let mut buf = [0; 48];
        let response = server.handle(
            "127.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((5, false, ServerReason::ParseError, ServerResponse::Ignore))
        );
        assert!(matches!(response, ServerAction::Ignore));

        let config = ServerConfig {
            denylist: FilterList {
                filter: vec!["127.0.0.0/24".parse().unwrap()],
                action: FilterAction::Ignore,
            },
            allowlist: FilterList {
                filter: vec!["0.0.0.0/0".parse().unwrap()],
                action: FilterAction::Ignore,
            },
            rate_limiting_cutoff: Duration::from_millis(100),
            rate_limiting_cache_size: 0,
            require_nts: None,
        };
        server.update_config(config);

        let mut buf = [0; 48];
        let response = server.handle(
            "127.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((5, false, ServerReason::Policy, ServerResponse::Ignore))
        );
        assert!(matches!(response, ServerAction::Ignore));
    }

    #[test]
    fn test_server_nts() {
        let config = ServerConfig {
            denylist: FilterList {
                filter: vec![],
                action: FilterAction::Deny,
            },
            allowlist: FilterList {
                filter: vec!["0.0.0.0/0".parse().unwrap()],
                action: FilterAction::Ignore,
            },
            rate_limiting_cutoff: Duration::from_millis(100),
            rate_limiting_cache_size: 0,
            require_nts: Some(FilterAction::Ignore),
        };
        let clock = TestClock {
            cur: NtpTimestamp::from_fixed_int(200),
        };
        let mut stats = TestStatHandler::default();
        let keyset = KeySetProvider::new(1).get();

        let mut server = Server::new(config, clock, SystemSnapshot::default(), keyset.clone());

        let decodedcookie = DecodedServerCookie {
            algorithm: AeadAlgorithm::AeadAesSivCmac256,
            s2c: Box::new(AesSivCmac256::new([0; 32].into())),
            c2s: Box::new(AesSivCmac256::new([0; 32].into())),
        };
        let cookie = keyset.encode_cookie(&decodedcookie);
        let (packet, id) =
            NtpPacket::nts_poll_message(&cookie, 0, PollIntervalLimits::default().min);
        let serialized = serialize_packet_encrypted(&packet, decodedcookie.c2s.as_ref());

        let mut buf = [0; 1024];
        let response = server.handle(
            "127.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((4, true, ServerReason::Policy, ServerResponse::ProvideTime))
        );
        let data = match response {
            ServerAction::Ignore => panic!("Server ignored packet"),
            ServerAction::Respond { message } => message,
        };
        let packet = NtpPacket::deserialize(data, decodedcookie.s2c.as_ref())
            .unwrap()
            .0;
        assert_ne!(packet.stratum(), 0);
        assert!(packet.valid_server_response(id, true));
        assert_eq!(
            packet.receive_timestamp(),
            NtpTimestamp::from_fixed_int(100)
        );
        assert_eq!(
            packet.transmit_timestamp(),
            NtpTimestamp::from_fixed_int(200)
        );

        let cookie_invalid = KeySetProvider::new(1).get().encode_cookie(&decodedcookie);
        let (packet_invalid, _) =
            NtpPacket::nts_poll_message(&cookie_invalid, 0, PollIntervalLimits::default().min);
        let serialized = serialize_packet_encrypted(&packet_invalid, decodedcookie.c2s.as_ref());

        let mut buf = [0; 1024];
        let response = server.handle(
            "127.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((4, true, ServerReason::InvalidCrypto, ServerResponse::NTSNak))
        );
        let data = match response {
            ServerAction::Ignore => panic!("Server ignored packet"),
            ServerAction::Respond { message } => message,
        };
        let packet = NtpPacket::deserialize(data, decodedcookie.s2c.as_ref())
            .unwrap()
            .0;
        assert!(packet.is_kiss_ntsn());
    }

    #[test]
    fn test_server_require_nts() {
        let mut config = ServerConfig {
            denylist: FilterList {
                filter: vec![],
                action: FilterAction::Deny,
            },
            allowlist: FilterList {
                filter: vec!["0.0.0.0/0".parse().unwrap()],
                action: FilterAction::Ignore,
            },
            rate_limiting_cutoff: Duration::from_secs(1),
            rate_limiting_cache_size: 0,
            require_nts: Some(FilterAction::Ignore),
        };
        let clock = TestClock {
            cur: NtpTimestamp::from_fixed_int(200),
        };
        let mut stats = TestStatHandler::default();

        let mut server = Server::new(
            config.clone(),
            clock,
            SystemSnapshot::default(),
            KeySetProvider::new(1).get(),
        );

        let (packet, _) = NtpPacket::poll_message(PollIntervalLimits::default().min);
        let serialized = serialize_packet_unencrypted(&packet);

        let mut buf = [0; 1024];
        let response = server.handle(
            "127.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((4, false, ServerReason::Policy, ServerResponse::Ignore))
        );
        assert!(matches!(response, ServerAction::Ignore));

        let decodedcookie = DecodedServerCookie {
            algorithm: AeadAlgorithm::AeadAesSivCmac256,
            s2c: Box::new(AesSivCmac256::new([0; 32].into())),
            c2s: Box::new(AesSivCmac256::new([0; 32].into())),
        };
        let cookie_invalid = KeySetProvider::new(1).get().encode_cookie(&decodedcookie);
        let (packet_invalid, _) =
            NtpPacket::nts_poll_message(&cookie_invalid, 0, PollIntervalLimits::default().min);
        let serialized = serialize_packet_encrypted(&packet_invalid, decodedcookie.c2s.as_ref());
        let response = server.handle(
            "127.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((4, true, ServerReason::InvalidCrypto, ServerResponse::NTSNak))
        );
        let data = match response {
            ServerAction::Ignore => panic!("Server ignored packet"),
            ServerAction::Respond { message } => message,
        };
        let packet = NtpPacket::deserialize(data, decodedcookie.s2c.as_ref())
            .unwrap()
            .0;
        assert!(packet.is_kiss_ntsn());

        config.require_nts = Some(FilterAction::Deny);
        server.update_config(config.clone());

        let (packet, id) = NtpPacket::poll_message(PollIntervalLimits::default().min);
        let serialized = serialize_packet_unencrypted(&packet);
        let response = server.handle(
            "127.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((4, false, ServerReason::Policy, ServerResponse::Deny))
        );
        let ServerAction::Respond { message } = response else {
            panic!("Server ignored packet")
        };

        let packet = NtpPacket::deserialize(message, &NoCipher).unwrap().0;
        assert!(packet.valid_server_response(id, false));
        assert!(packet.is_kiss_deny());
    }

    #[cfg(feature = "ntpv5")]
    #[test]
    fn test_server_v5() {
        let config = ServerConfig {
            denylist: FilterList {
                filter: vec![],
                action: FilterAction::Deny,
            },
            allowlist: FilterList {
                filter: vec!["127.0.0.0/24".parse().unwrap()],
                action: FilterAction::Deny,
            },
            rate_limiting_cutoff: Duration::from_millis(100),
            rate_limiting_cache_size: 0,
            require_nts: None,
        };
        let clock = TestClock {
            cur: NtpTimestamp::from_fixed_int(200),
        };
        let mut stats = TestStatHandler::default();

        let mut server = Server::new(
            config,
            clock,
            SystemSnapshot::default(),
            KeySetProvider::new(1).get(),
        );

        let (packet, id) = NtpPacket::poll_message_v5(PollIntervalLimits::default().min);
        let serialized = serialize_packet_unencrypted(&packet);

        let mut buf = [0; 1024];
        let response = server.handle(
            "127.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((5, false, ServerReason::Policy, ServerResponse::ProvideTime))
        );
        let data = match response {
            ServerAction::Ignore => panic!("Server ignored packet"),
            ServerAction::Respond { message } => message,
        };
        let packet = NtpPacket::deserialize(data, &NoCipher).unwrap().0;
        assert_ne!(packet.stratum(), 0);
        assert!(packet.valid_server_response(id, false));
        assert_eq!(
            packet.receive_timestamp(),
            NtpTimestamp::from_fixed_int(100)
        );
        assert_eq!(
            packet.transmit_timestamp(),
            NtpTimestamp::from_fixed_int(200)
        );

        let mut buf = [0; 1024];
        let response = server.handle(
            "128.0.0.1".parse().unwrap(),
            NtpTimestamp::from_fixed_int(100),
            &serialized,
            &mut buf,
            &mut stats,
        );
        assert_eq!(
            stats.last_register.take(),
            Some((5, false, ServerReason::Policy, ServerResponse::Deny))
        );
        let data = match response {
            ServerAction::Ignore => panic!("Server ignored packet"),
            ServerAction::Respond { message } => message,
        };
        let packet = NtpPacket::deserialize(data, &NoCipher).unwrap().0;
        assert!(packet.valid_server_response(id, false));
        assert!(packet.is_kiss_deny());
    }

    // TimestampedCache tests
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

    // IpSubnet parsing tests
    #[test]
    fn test_ipv4_subnet_parse() {
        use std::str::FromStr;

        assert!(IpSubnet::from_str("bla/5").is_err());
        assert!(IpSubnet::from_str("0.0.0.0").is_err());
        assert!(IpSubnet::from_str("0.0.0.0/33").is_err());
        assert_eq!(
            IpSubnet::from_str("0.0.0.0/0"),
            Ok(IpSubnet {
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                mask: 0
            })
        );
        assert_eq!(
            IpSubnet::from_str("127.0.0.1/32"),
            Ok(IpSubnet {
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                mask: 32
            })
        );

        assert_de_tokens_error::<IpSubnet>(
            &[Token::Str("bla/5")],
            "invalid IP address syntax in subnet",
        );
        assert_de_tokens_error::<IpSubnet>(&[Token::Str("0.0.0.0")], "Invalid subnet syntax");
        assert_de_tokens_error::<IpSubnet>(&[Token::Str("0.0.0.0/33")], "Invalid subnet mask");
        assert_de_tokens(
            &IpSubnet {
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                mask: 0,
            },
            &[Token::Str("0.0.0.0/0")],
        );
        assert_de_tokens(
            &IpSubnet {
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                mask: 32,
            },
            &[Token::Str("127.0.0.1/32")],
        );
    }

    #[test]
    fn test_ipv6_subnet_parse() {
        use std::str::FromStr;

        assert!(IpSubnet::from_str("bla/5").is_err());
        assert!(IpSubnet::from_str("::").is_err());
        assert!(IpSubnet::from_str("::/129").is_err());
        assert_eq!(
            IpSubnet::from_str("::/0"),
            Ok(IpSubnet {
                addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                mask: 0
            })
        );
        assert_eq!(
            IpSubnet::from_str("::1/128"),
            Ok(IpSubnet {
                addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                mask: 128
            })
        );

        assert_de_tokens_error::<IpSubnet>(
            &[Token::Str("bla/5")],
            "invalid IP address syntax in subnet",
        );
        assert_de_tokens_error::<IpSubnet>(&[Token::Str("::")], "Invalid subnet syntax");
        assert_de_tokens_error::<IpSubnet>(&[Token::Str("::/129")], "Invalid subnet mask");
        assert_de_tokens(
            &IpSubnet {
                addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                mask: 0,
            },
            &[Token::Str("::/0")],
        );
        assert_de_tokens(
            &IpSubnet {
                addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                mask: 128,
            },
            &[Token::Str("::1/128")],
        );
    }
}
