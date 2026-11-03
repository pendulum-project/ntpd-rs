use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    task::Poll,
    time::Duration,
};

use ntp_proto::{PollIntervalLimits, ProtocolVersion};
use serde::{
    Deserialize, Serialize,
    de::{self, Visitor},
};
use statime_config::{Configurable, ConfigurableAtomic, Positive};

#[cfg(target_os = "linux")]
use crate::daemon::spawn::csptp::CsptpSpawnerConfig;
use crate::daemon::{
    Config,
    config::{ConfigurableDuration, Unit},
    keyexchange::certificates_from_file,
    spawn::{ntp::NtpSpawnerConfig, ntp_pool::NtpPoolSpawnerConfig, nts::NtpNtsSpawnerConfig},
};

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

#[derive(Debug, PartialEq, Clone, Configurable)]
pub(crate) struct NtpSourceConfig {
    pub(crate) address: NetworkAddress,
    #[config(rename = "ntp-version", default)]
    pub(crate) ntp_version: RequestedNtpVersion,
    #[config(rename = "minimum-poll-interval", default)]
    pub(crate) minimum_poll_interval: Option<Positive<ConfigurableDuration>>,
    #[config(rename = "maximum-poll-interval", default)]
    pub(crate) maximum_poll_interval: Option<Positive<ConfigurableDuration>>,
    #[config(rename = "desired-error", default)]
    pub(crate) desired_error: Option<Positive<ConfigurableDuration>>,
    // Experimental
    #[config(rename = "delay-decay-rate", default)]
    pub(crate) delay_decay_rate: Option<Positive<f64>>,
}

impl NtpSourceConfig {
    pub fn generate_spawner_config(&self, config: &Config) -> NtpSpawnerConfig {
        let poll_low = ConfigurableDuration::into_larger_poll_interval(
            self.minimum_poll_interval
                .unwrap_or(config.ntp_source_defaults.minimum_poll_interval),
        );

        let poll_high = ConfigurableDuration::into_smaller_poll_interval(
            self.maximum_poll_interval
                .unwrap_or(config.ntp_source_defaults.maximum_poll_interval),
        )
        .max(poll_low);

        NtpSpawnerConfig {
            address: self.address.clone().into(),
            ntp_version: self.ntp_version.into(),
            poll_interval_limits: PollIntervalLimits {
                min: poll_low,
                max: poll_high,
            },
            desired_error_bound: self
                .desired_error
                .unwrap_or(config.ntp_source_defaults.desired_error)
                .into_inner()
                .into(),
            delay_decay_rate: self
                .delay_decay_rate
                .unwrap_or(config.ntp_source_defaults.delay_decay_rate)
                .into_inner(),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Configurable)]
pub(crate) struct NtpPoolSourceConfig {
    pub(crate) address: NetworkAddress,
    #[config(rename = "ntp-version", default)]
    pub(crate) ntp_version: RequestedNtpVersion,
    #[config(default = 4)]
    pub(crate) count: usize,
    #[config(default)]
    pub(crate) ignore: Vec<IpAddr>,
    #[config(rename = "minimum-poll-interval")]
    pub(crate) minimum_poll_interval: Option<Positive<ConfigurableDuration>>,
    #[config(rename = "maximum-poll-interval", default)]
    pub(crate) maximum_poll_interval: Option<Positive<ConfigurableDuration>>,
    #[config(rename = "desired-error", default)]
    pub(crate) desired_error: Option<Positive<ConfigurableDuration>>,
    // Experimental
    #[config(rename = "delay-decay-rate", default)]
    pub(crate) delay_decay_rate: Option<Positive<f64>>,
}

impl NtpPoolSourceConfig {
    pub fn generate_spawner_config(&self, config: &Config) -> NtpPoolSpawnerConfig {
        let poll_low = ConfigurableDuration::into_larger_poll_interval(
            self.minimum_poll_interval
                .unwrap_or(config.ntp_source_defaults.minimum_poll_interval),
        );

        let poll_high = ConfigurableDuration::into_smaller_poll_interval(
            self.maximum_poll_interval
                .unwrap_or(config.ntp_source_defaults.maximum_poll_interval),
        )
        .max(poll_low);

        NtpPoolSpawnerConfig {
            addr: self.address.clone().into(),
            count: self.count,
            ignore: self.ignore.clone(),
            ntp_version: self.ntp_version.into(),
            poll_interval_limits: PollIntervalLimits {
                min: poll_low,
                max: poll_high,
            },
            desired_error_bound: self
                .desired_error
                .unwrap_or(config.ntp_source_defaults.desired_error)
                .into_inner()
                .into(),
            delay_decay_rate: self
                .delay_decay_rate
                .unwrap_or(config.ntp_source_defaults.delay_decay_rate)
                .into_inner(),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Configurable)]
pub(crate) struct NtpNtsSourceConfig {
    pub(crate) address: NetworkAddress,
    #[config(rename = "additional-certificates", default)]
    pub(crate) additional_certificates: Option<PathBuf>,
    #[config(rename = "enable-srv-resolution", default = false)]
    pub(crate) enable_srv_resolution: bool,
    #[config(rename = "ntp-version", default)]
    pub(crate) ntp_version: RequestedNtpVersion,
    #[config(rename = "minimum-poll-interval")]
    pub(crate) minimum_poll_interval: Option<Positive<ConfigurableDuration>>,
    #[config(rename = "maximum-poll-interval", default)]
    pub(crate) maximum_poll_interval: Option<Positive<ConfigurableDuration>>,
    #[config(rename = "desired-error", default)]
    pub(crate) desired_error: Option<Positive<ConfigurableDuration>>,
    // Experimental
    #[config(rename = "delay-decay-rate", default)]
    pub(crate) delay_decay_rate: Option<Positive<f64>>,
}

impl NtpNtsSourceConfig {
    pub fn generate_spawner_config(
        &self,
        config: &Config,
    ) -> Result<NtpNtsSpawnerConfig, std::io::Error> {
        let poll_low = ConfigurableDuration::into_larger_poll_interval(
            self.minimum_poll_interval
                .unwrap_or(config.ntp_source_defaults.minimum_poll_interval),
        );

        let poll_high = ConfigurableDuration::into_smaller_poll_interval(
            self.maximum_poll_interval
                .unwrap_or(config.ntp_source_defaults.maximum_poll_interval),
        )
        .max(poll_low);

        let additional_certificates =
            if let Some(certificate_path) = self.additional_certificates.clone() {
                match certificates_from_file(&certificate_path) {
                    Ok(certificates) => Ok(Arc::from(certificates)),
                    Err(io_error) => {
                        let msg = format!(
                            "error while parsing certificate file {}: {:?}",
                            certificate_path.display(),
                            io_error
                        );
                        Err(std::io::Error::other(msg))
                    }
                }
            } else {
                Ok(Arc::default())
            }?;

        Ok(NtpNtsSpawnerConfig {
            address: self.address.clone().into(),
            enable_srv_resolution: self.enable_srv_resolution,
            certificate_authorities: additional_certificates,
            ntp_version: self.ntp_version.into(),
            poll_interval_limits: PollIntervalLimits {
                min: poll_low,
                max: poll_high,
            },
            desired_error_bound: self
                .desired_error
                .unwrap_or(config.ntp_source_defaults.desired_error)
                .into_inner()
                .into(),
            delay_decay_rate: self
                .delay_decay_rate
                .unwrap_or(config.ntp_source_defaults.delay_decay_rate)
                .into_inner(),
        })
    }
}

#[derive(Debug, PartialEq, Clone, Configurable)]
pub(crate) struct NtpNtsPoolSourceConfig {}

#[derive(Debug, PartialEq, Clone, Configurable)]
pub(crate) struct SockSourceConfig {}

#[cfg(feature = "pps")]
#[derive(Debug, PartialEq, Clone, Configurable)]
pub(crate) struct PpsSourceConfig {}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Clone, Configurable)]
pub(crate) struct CsptpSourceConfig {
    pub(crate) address: String,
    #[config(default)]
    pub(crate) domain: Option<u8>,
    #[config(rename = "poll-interval", default)]
    pub(crate) poll_interval: Option<Positive<ConfigurableDuration>>,
    #[config(rename = "response-interval", default)]
    pub(crate) response_interval: Option<Positive<ConfigurableDuration>>,
    // Experimental
    #[config(rename = "delay-decay-rate", default)]
    pub(crate) delay_decay_rate: Option<Positive<f64>>,
}

#[cfg(target_os = "linux")]
impl CsptpSourceConfig {
    pub fn generate_spawner_config(&self, config: &Config) -> CsptpSpawnerConfig {
        CsptpSpawnerConfig {
            address: self.address.clone(),
            domain: self.domain.unwrap_or(config.csptp_source_defaults.domain),
            poll_interval: ConfigurableDuration::into_std_duration(
                self.poll_interval
                    .unwrap_or(config.csptp_source_defaults.poll_interval),
            ),
            response_interval: ConfigurableDuration::into_std_duration(
                self.response_interval
                    .unwrap_or(config.csptp_source_defaults.response_interval),
            ),
            delay_decay_rate: self
                .delay_decay_rate
                .unwrap_or(config.csptp_source_defaults.delay_decay_rate)
                .into_inner(),
        }
    }
}

#[derive(Debug, Default, PartialEq, Clone, Copy, ConfigurableAtomic)]
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
