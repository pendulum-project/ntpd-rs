use std::{
    fmt::Display,
    marker::PhantomData,
    net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use ntp_proto::PollInterval;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, Visitor},
};
use statime_algo::JumpThreshold;
use statime_base::Duration;
use statime_config::{
    ConfigurableAtomic, InfiniteOr, IsNonNegative, IsPositive, NonNegative, Positive,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) enum Unit {
    Nanosecond,
    Microsecond,
    Millisecond,
    Second,
    Minute,
    Hour,
    Day,
    Week,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct ConfigurableDuration {
    pub(super) unit: Unit,
    pub(super) duration: f64,
}

impl IsPositive for ConfigurableDuration {
    fn is_positive(&self) -> bool {
        self.duration > 0.0
    }
}

impl IsNonNegative for ConfigurableDuration {
    fn is_non_negative(&self) -> bool {
        self.duration >= 0.0
    }
}

impl Serialize for ConfigurableDuration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!(
            "{}{}",
            self.duration,
            match self.unit {
                Unit::Nanosecond => "ns",
                Unit::Microsecond => "us",
                Unit::Millisecond => "ms",
                Unit::Second => "s",
                Unit::Minute => "m",
                Unit::Hour => "h",
                Unit::Day => "d",
                Unit::Week => "w",
            }
        ))
    }
}

fn check_float<E: de::Error>(value: f64) -> Result<f64, E> {
    if value.is_nan() || value.is_infinite() {
        Err(de::Error::custom(
            "Invalid duration, cannot be infinite or a nan",
        ))
    } else {
        Ok(value)
    }
}

struct ConfigurableDurationVisitor;

impl<'de> Visitor<'de> for ConfigurableDurationVisitor {
    type Value = ConfigurableDuration;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("Duration")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if let Some(duration) = v.strip_suffix("ns") {
            Ok(ConfigurableDuration {
                unit: Unit::Nanosecond,
                duration: duration
                    .parse()
                    .map_err(de::Error::custom)
                    .and_then(check_float)?,
            })
        } else if let Some(duration) = v.strip_suffix("us") {
            Ok(ConfigurableDuration {
                unit: Unit::Microsecond,
                duration: duration
                    .parse()
                    .map_err(de::Error::custom)
                    .and_then(check_float)?,
            })
        } else if let Some(duration) = v.strip_suffix("ms") {
            Ok(ConfigurableDuration {
                unit: Unit::Millisecond,
                duration: duration
                    .parse()
                    .map_err(de::Error::custom)
                    .and_then(check_float)?,
            })
        } else if let Some(duration) = v.strip_suffix("s") {
            Ok(ConfigurableDuration {
                unit: Unit::Second,
                duration: duration
                    .parse()
                    .map_err(de::Error::custom)
                    .and_then(check_float)?,
            })
        } else if let Some(duration) = v.strip_suffix("m") {
            Ok(ConfigurableDuration {
                unit: Unit::Minute,
                duration: duration
                    .parse()
                    .map_err(de::Error::custom)
                    .and_then(check_float)?,
            })
        } else if let Some(duration) = v.strip_suffix("h") {
            Ok(ConfigurableDuration {
                unit: Unit::Hour,
                duration: duration
                    .parse()
                    .map_err(de::Error::custom)
                    .and_then(check_float)?,
            })
        } else if let Some(duration) = v.strip_suffix("d") {
            Ok(ConfigurableDuration {
                unit: Unit::Day,
                duration: duration
                    .parse()
                    .map_err(de::Error::custom)
                    .and_then(check_float)?,
            })
        } else if let Some(duration) = v.strip_suffix("w") {
            Ok(ConfigurableDuration {
                unit: Unit::Week,
                duration: duration
                    .parse()
                    .map_err(de::Error::custom)
                    .and_then(check_float)?,
            })
        } else {
            Err(de::Error::custom(format!("Invalid duration {v}")))
        }
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(v)
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(&v)
    }
}

impl<'de> Deserialize<'de> for ConfigurableDuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_str(ConfigurableDurationVisitor)
    }
}

impl ConfigurableAtomic for ConfigurableDuration {}

impl ConfigurableDuration {
    pub(crate) fn seconds(self) -> f64 {
        match self.unit {
            Unit::Nanosecond => self.duration * 1e-9,
            Unit::Microsecond => self.duration * 1e-6,
            Unit::Millisecond => self.duration * 1e-3,
            Unit::Second => self.duration,
            Unit::Minute => self.duration * 60.0,
            Unit::Hour => self.duration * (60.0 * 60.0),
            Unit::Day => self.duration * (24.0 * 60.0 * 60.0),
            Unit::Week => self.duration * (7.0 * 24.0 * 60.0 * 60.0),
        }
    }
}

impl From<ConfigurableDuration> for statime_base::Duration {
    fn from(value: ConfigurableDuration) -> Self {
        statime_base::Duration::from_f64_seconds(value.seconds())
    }
}

impl ConfigurableDuration {
    pub(crate) fn into_std_duration(value: Positive<ConfigurableDuration>) -> std::time::Duration {
        std::time::Duration::from_secs_f64(value.into_inner().seconds())
    }

    pub(crate) fn into_larger_poll_interval(this: Positive<ConfigurableDuration>) -> PollInterval {
        let v = (this.into_inner().seconds().log2() - 1.01f64.log2()).ceil() as i8;
        PollInterval::from_byte(v.cast_unsigned())
    }

    pub(crate) fn into_smaller_poll_interval(this: Positive<ConfigurableDuration>) -> PollInterval {
        let v = (this.into_inner().seconds().log2() + 1.01f64.log2()).floor() as i8;
        PollInterval::from_byte(v.cast_unsigned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ConfigurableAtomic)]
pub(crate) struct NetworkAddress {
    pub(crate) server: String,
    pub(crate) port: Option<u16>,
}

impl Serialize for NetworkAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.port {
            Some(port) if self.server.contains(':') => {
                serializer.serialize_str(&format!("[{}]:{}", self.server, port))
            }
            Some(port) => serializer.serialize_str(&format!("{}:{}", self.server, port)),
            None => serializer.serialize_str(&self.server),
        }
    }
}

impl<'de> Deserialize<'de> for NetworkAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let raw_address = String::deserialize(deserializer)?;

        if raw_address.split(':').count() > 2 {
            // Ipv6, parse it
            match raw_address.parse::<SocketAddr>() {
                Ok(socket_addr) => Ok(NetworkAddress {
                    server: socket_addr.ip().to_string(),
                    port: Some(socket_addr.port()),
                }),
                Err(e) => {
                    // Could be because of no port, add one and see
                    let address_with_port = format!("[{raw_address}]:1");
                    if let Ok(socket_addr) = address_with_port.parse::<SocketAddr>() {
                        Ok(NetworkAddress {
                            server: socket_addr.ip().to_string(),
                            port: None,
                        })
                    } else {
                        Err(serde::de::Error::custom(e))
                    }
                }
            }
        } else if let Some((server_name, port)) = raw_address.split_once(':') {
            Ok(NetworkAddress {
                server: server_name.into(),
                port: Some(port.parse().map_err(serde::de::Error::custom)?),
            })
        } else {
            Ok(NetworkAddress {
                server: raw_address,
                port: None,
            })
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ConfigurableAtomic)]
pub(crate) struct IpSubnet {
    pub(crate) addr: IpAddr,
    pub(crate) mask: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubnetParseError {
    Subnet,
    Ip(AddrParseError),
    Mask,
    MaskV4Range,
}

impl std::error::Error for SubnetParseError {}

impl Display for SubnetParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Subnet => write!(f, "Invalid subnet syntax"),
            Self::Ip(e) => write!(f, "{e} in subnet"),
            Self::Mask => write!(f, "Invalid subnet mask"),
            Self::MaskV4Range => write!(
                f,
                "Subnet mask overflows the IPv4 range of an IPv4-mapped IPv6 address"
            ),
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

    /// Parse a CIDR string (e.g. 192.168.1.0/24) and parse it as a subnet.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, mask) = s.split_once('/').ok_or(SubnetParseError::Subnet)?;
        let addr: IpAddr = addr.parse()?;
        let mask: u8 = mask.parse().map_err(|_| SubnetParseError::Mask)?;

        let max_mask = match addr {
            IpAddr::V4(_) => Ipv4Addr::BITS,
            IpAddr::V6(_) => Ipv6Addr::BITS,
        };
        if u32::from(mask) > max_mask {
            return Err(SubnetParseError::Mask);
        }

        let min_mask = match addr {
            IpAddr::V4(ipv4_addr) => max_mask - ipv4_addr.to_bits().trailing_zeros(),
            IpAddr::V6(ipv6_addr) => max_mask - ipv6_addr.to_bits().trailing_zeros(),
        };
        if u32::from(mask) < min_mask {
            return Err(SubnetParseError::Mask);
        }

        // Canonicalize IPv4-mapped IPv6 addresses (e.g. `::ffff:192.168.0.0`)
        // to their IPv4 form so they match against canonicalized filtered IPs.
        let (addr, mask) = match (addr, addr.to_canonical()) {
            (IpAddr::V6(_), canonical @ IpAddr::V4(_)) => {
                // FIXME: make this a checked conversion once const_convert is stabilized long
                // enough (https://github.com/rust-lang/rust/issues/143773)
                const BITMASK_DIFF: u8 = (Ipv6Addr::BITS - Ipv4Addr::BITS) as u8;
                let mask = mask
                    .checked_sub(BITMASK_DIFF)
                    .ok_or(SubnetParseError::MaskV4Range)?;
                (canonical, mask)
            }
            _ => (addr, mask),
        };

        Ok(IpSubnet { addr, mask })
    }
}

impl Display for IpSubnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.mask)
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

impl Serialize for IpSubnet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl From<IpSubnet> for ntp_proto::IpSubnet {
    fn from(value: IpSubnet) -> Self {
        Self {
            addr: value.addr,
            mask: value.mask,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize, ConfigurableAtomic)]
#[serde(untagged)]
pub(crate) enum PotentiallyAsymetricThreshold {
    Symmetric(InfiniteOr<NonNegative<ConfigurableDuration>>),
    Asymmetric {
        forward: InfiniteOr<NonNegative<ConfigurableDuration>>,
        backward: InfiniteOr<NonNegative<ConfigurableDuration>>,
    },
}

impl From<PotentiallyAsymetricThreshold> for JumpThreshold {
    fn from(value: PotentiallyAsymetricThreshold) -> Self {
        match value {
            PotentiallyAsymetricThreshold::Symmetric(bound) => {
                let bound = match bound {
                    InfiniteOr::Infinite => None,
                    InfiniteOr::Finite(duration) => {
                        Some(statime_base::Duration::from(duration.into_inner()))
                    }
                };

                JumpThreshold {
                    backwards: bound,
                    forwards: bound,
                }
            }
            PotentiallyAsymetricThreshold::Asymmetric { forward, backward } => JumpThreshold {
                backwards: match backward {
                    InfiniteOr::Infinite => None,
                    InfiniteOr::Finite(duration) => {
                        Some(statime_base::Duration::from(duration.into_inner()))
                    }
                },
                forwards: match forward {
                    InfiniteOr::Infinite => None,
                    InfiniteOr::Finite(duration) => {
                        Some(statime_base::Duration::from(duration.into_inner()))
                    }
                },
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ConfigurableAtomic)]
pub(crate) enum NtpVersion {
    V3,
    V4,
    V5,
}

impl<'de> Deserialize<'de> for NtpVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let version = u8::deserialize(deserializer)?;
        match version {
            3 => Ok(Self::V3),
            4 => Ok(Self::V4),
            5 => Ok(Self::V5),
            _ => Err(de::Error::custom(format!(
                "Invalid ntp version {}",
                version
            ))),
        }
    }
}

impl Serialize for NtpVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(match self {
            NtpVersion::V3 => 3,
            NtpVersion::V4 => 4,
            NtpVersion::V5 => 5,
        })
    }
}

impl From<NtpVersion> for ntp_proto::NtpVersion {
    fn from(value: NtpVersion) -> Self {
        match value {
            NtpVersion::V3 => Self::V3,
            NtpVersion::V4 => Self::V4,
            NtpVersion::V5 => Self::V5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ConfigurableAtomic)]
pub(crate) enum NtsNtpVersion {
    V4,
    V5,
}

impl<'de> Deserialize<'de> for NtsNtpVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let version = u8::deserialize(deserializer)?;
        match version {
            4 => Ok(Self::V4),
            5 => Ok(Self::V5),
            _ => Err(de::Error::custom(format!(
                "Invalid ntp version for nts {}",
                version
            ))),
        }
    }
}

impl Serialize for NtsNtpVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(match self {
            Self::V4 => 4,
            Self::V5 => 5,
        })
    }
}

impl From<NtsNtpVersion> for ntp_proto::NtpVersion {
    fn from(value: NtsNtpVersion) -> Self {
        match value {
            NtsNtpVersion::V4 => Self::V4,
            NtsNtpVersion::V5 => Self::V5,
        }
    }
}
