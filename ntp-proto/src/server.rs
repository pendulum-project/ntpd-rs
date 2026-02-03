use std::{
    collections::hash_map::RandomState,
    fmt::Display,
    io::Cursor,
    net::{AddrParseError, IpAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use serde::{Deserialize, Deserializer, de};

use crate::{
    KeySet, NoCipher, NtpClock, NtpPacket, NtpTimestamp, NtpVersion, PacketParsingError,
    SystemSnapshot, ipfilter::IpFilter,
};

pub enum ServerAction<'a> {
    Ignore,
    Respond { message: &'a [u8] },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServerReason {
    RateLimit,
    ParseError,
    InvalidCrypto,
    InternalError,
    Policy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServerResponse {
    NTSNak,
    Deny,
    Ignore,
    ProvideTime,
}

pub trait ServerStatHandler {
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
    pub accepted_versions: Vec<NtpVersion>,
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

fn fallback_message_version(message: &[u8]) -> u8 {
    message.first().map_or(0, |v| (v & 0b0011_1000) >> 3)
}

impl<C> Server<C> {
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

    pub fn update_system(&mut self, system: SystemSnapshot) {
        self.system = system;
    }

    pub fn update_keyset(&mut self, keyset: Arc<KeySet>) {
        self.keyset = keyset;
    }

    fn intended_action(&mut self, client_ip: IpAddr) -> (ServerResponse, ServerReason) {
        if self.denyfilter.is_in(&client_ip) {
            (self.config.denylist.action.into(), ServerReason::Policy)
        } else if !self.allowfilter.is_in(&client_ip) {
            (self.config.allowlist.action.into(), ServerReason::Policy)
        } else if !self.client_cache.is_allowed(
            client_ip,
            Instant::now(),
            self.config.rate_limiting_cutoff,
        ) {
            (ServerResponse::Ignore, ServerReason::RateLimit)
        } else {
            (ServerResponse::ProvideTime, ServerReason::Policy)
        }
    }
}

impl<C: NtpClock> Server<C> {
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
            stats_handler.register(fallback_message_version(message), false, reason, action);
            return ServerAction::Ignore;
        }

        // EARLY DROP truncated packets
        if message.len() < 48 {
            stats_handler.register(
                fallback_message_version(message),
                false,
                ServerReason::ParseError,
                ServerResponse::Ignore,
            );
            return ServerAction::Ignore;
        }

        let (packet, cookie) = match NtpPacket::deserialize(message, self.keyset.as_ref()) {
            Ok((packet, cookie)) => match packet.mode() {
                crate::NtpAssociationMode::Client => (packet, cookie),
                _ => {
                    stats_handler.register(
                        fallback_message_version(message),
                        false,
                        ServerReason::ParseError,
                        ServerResponse::Ignore,
                    );
                    return ServerAction::Ignore;
                }
            },
            Err(PacketParsingError::DecryptError(packet)) => {
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

        let version = packet.version();

        if !self.config.accepted_versions.contains(&version) {
            stats_handler.register(
                version.as_u8(),
                false,
                ServerReason::Policy,
                ServerResponse::Ignore,
            );
            return ServerAction::Ignore;
        }

        let nts = cookie.is_some() || action == ServerResponse::NTSNak;

        if let (false, Some(non_nts_action)) = (nts, self.config.require_nts) {
            if non_nts_action == FilterAction::Ignore {
                stats_handler.register(
                    version.into(),
                    nts,
                    ServerReason::Policy,
                    ServerResponse::Ignore,
                );
                return ServerAction::Ignore;
            }
            action = ServerResponse::Deny;
            reason = ServerReason::Policy;
        }

	let buf_len = buffer.len();
	let mut cursor = Cursor::new(&mut *buffer);


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
                        Some(buf_len),
                    )
                } else {
                    NtpPacket::timestamp_response(&self.system, packet, recv_timestamp, &self.clock)
                        .serialize(&mut cursor, &NoCipher, Some(buf_len))
                }
            }
            ServerResponse::Ignore => unreachable!(),
        };

        match result {
            Ok(_) => {
                stats_handler.register(version.into(), nts, reason, action);
                let length = cursor.position();
                ServerAction::Respond {
                    message: &cursor.into_inner()[..length as _],
                }
            }
            Err(e) => {
                tracing::error!("Could not serialize response: {}", e);
                stats_handler.register(
                    version.into(),
                    nts,
                    ServerReason::InternalError,
                    ServerResponse::Ignore,
                );
                ServerAction::Ignore
            }
        }
    }
}

// ===== helper types below unchanged =====

#[derive(Debug)]
struct TimestampedCache<T> {
    randomstate: RandomState,
    elements: Vec<Option<(T, Instant)>>,
}

impl<T: std::hash::Hash + Eq> TimestampedCache<T> {
    fn new(length: usize) -> Self {
        Self {
            elements: std::iter::repeat_with(|| None).take(length).collect(),
            randomstate: RandomState::new(),
        }
    }

    fn index(&self, item: &T) -> usize {
        use std::hash::BuildHasher;
        self.randomstate.hash_one(item) as usize % self.elements.len()
    }

    fn is_allowed(&mut self, item: T, timestamp: Instant, cutoff: Duration) -> bool {
        if self.elements.is_empty() {
            return true;
        }

        let index = self.index(&item);

        let timestamp_if_same = self.elements[index]
            .as_ref()
            .and_then(|(v, t)| (&item == v).then_some(t))
            .copied();

        self.elements[index] = Some((item, timestamp));

        if let Some(old_timestamp) = timestamp_if_same {
            timestamp.duration_since(old_timestamp) >= cutoff
        } else {
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
