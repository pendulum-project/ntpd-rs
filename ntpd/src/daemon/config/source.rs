use std::{fmt, net::SocketAddr, time::Duration};

use ntp_proto::ProtocolVersion;
use serde::{
    Deserialize, Serialize,
    de::{self, Visitor},
};
use statime_config::{Configurable, ConfigurableAtomic, Positive};

use crate::daemon::config::{ConfigurableDuration, Unit};

use super::NetworkAddress;

mod configurable;

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum SourceConfig {
    NtpServer(NtpSourceConfig),
    NtpPool(NtpPoolSourceConfig),
    NtpNtsServer(NtpNtsSourceConfig),
    NtpNtsPool(NtpNtsPoolSourceConfig),
    Sock(SockSourceConfig),
    #[cfg(feature = "pps")]
    Pps(PpsSourceConfig),
    #[cfg(target_os = "linux")]
    Csptp(CsptpSourceConfig),
}

struct PartialSourceConfig {
    kind: PartialSourceConfigEnum,
}

enum PartialSourceConfigEnum {
    NtpServer(<NtpSourceConfig as Configurable>::Node),
}

#[derive(Debug, PartialEq, Clone, Configurable)]
pub(crate) struct NtpSourceConfig {
    pub(crate) address: NetworkAddress,
    #[config(rename = "ntp-version")]
    pub(crate) ntp_version: RequestedNtpVersion,
    #[config(rename = "minimum-poll-interval", default)]
    pub(crate) minimum_poll_interval: Option<Positive<ConfigurableDuration>>,
    #[config(rename = "maximum-poll-interval", default)]
    pub(crate) maximum_poll_interval: Option<Positive<ConfigurableDuration>>,
    #[config(rename = "desired-error", default = Positive::unchecked_new(ConfigurableDuration {unit: Unit::Millisecond, duration: 1.0}))]
    pub(crate) desired_error: Positive<ConfigurableDuration>,
    // Experimental
    #[config(rename = "delay-decay-rate", default = Positive::unchecked_new(1.0/86400.0))]
    pub(crate) delay_decay_rate: Positive<f64>,
}

#[derive(Debug, PartialEq, Clone, Configurable)]
pub(crate) struct NtpPoolSourceConfig {
    pub(crate) address: NetworkAddress,
    #[config(rename = "ntp-version")]
    pub(crate) ntp_version: RequestedNtpVersion,
    pub(crate) count: usize,
    #[config(rename = "minimum-poll-interval")]
    pub(crate) minimum_poll_interval: Option<Positive<ConfigurableDuration>>,
    #[config(rename = "maximum-poll-interval")]
    pub(crate) maximum_poll_interval: Option<Positive<ConfigurableDuration>>,
    #[config(rename = "desired-error", default = Positive::unchecked_new(ConfigurableDuration {unit: Unit::Millisecond, duration: 1.0}))]
    pub(crate) desired_error: Positive<ConfigurableDuration>,
    // Experimental
    #[config(rename = "delay-decay-rate", default = Positive::unchecked_new(1.0/86400.0))]
    pub(crate) delay_decay_rate: Positive<f64>,
}

#[derive(Debug, PartialEq, Clone, Configurable)]
pub(crate) struct NtpNtsSourceConfig {}

#[derive(Debug, PartialEq, Clone, Configurable)]
pub(crate) struct NtpNtsPoolSourceConfig {}

#[derive(Debug, PartialEq, Clone, Configurable)]
pub(crate) struct SockSourceConfig {}

#[cfg(feature = "pps")]
#[derive(Debug, PartialEq, Clone, Configurable)]
pub(crate) struct PpsSourceConfig {}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Clone, Configurable)]
pub(crate) struct CsptpSourceConfig {}

#[derive(Debug, Default, PartialEq, Clone, ConfigurableAtomic)]
pub(crate) enum RequestedNtpVersion {
    Auto,
    #[default]
    V4,
    V5,
}

impl<'de> Deserialize<'de> for RequestedNtpVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ProtocolVersionVisitor;

        impl Visitor<'_> for ProtocolVersionVisitor {
            type Value = RequestedNtpVersion;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(r#"4 or 5 as an integer, or the special string value "auto""#)
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match v {
                    4 => Ok(RequestedNtpVersion::V4),
                    5 => Ok(RequestedNtpVersion::V5),
                    _ => Err(E::custom(r#"Version must be 4, 5 or "auto""#)),
                }
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_u64(v.try_into().map_err(E::custom)?)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match v {
                    "auto" => Ok(RequestedNtpVersion::Auto),
                    _ => Err(E::custom(r#"Version must be 4, 5 or "auto""#)),
                }
            }
        }

        deserializer.deserialize_any(ProtocolVersionVisitor)
    }
}

impl Serialize for RequestedNtpVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            RequestedNtpVersion::Auto => serializer.serialize_str("auto"),
            RequestedNtpVersion::V4 => serializer.serialize_u8(4),
            RequestedNtpVersion::V5 => serializer.serialize_u8(5),
        }
    }
}

impl From<RequestedNtpVersion> for ProtocolVersion {
    fn from(value: RequestedNtpVersion) -> Self {
        match value {
            RequestedNtpVersion::Auto => Self::v4_upgrading_to_v5_with_default_tries(),
            RequestedNtpVersion::V4 => Self::V4,
            RequestedNtpVersion::V5 => Self::V5,
        }
    }
}
