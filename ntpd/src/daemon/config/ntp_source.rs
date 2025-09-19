use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    ops::Deref,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use ntp_proto::{PollInterval, PollIntervalLimits, SourceConfig};
use ntp_proto::{ProtocolVersion, tls_utils::Certificate};
use serde::{
    Deserialize, Deserializer,
    de::{self, Visitor},
};

use super::super::keyexchange::certificates_from_file;

fn deserialize_ntp_version<'de, D>(deserializer: D) -> Result<ProtocolVersion, D::Error>
where
    D: Deserializer<'de>,
{
    struct ProtocolVersionVisitor;

    impl Visitor<'_> for ProtocolVersionVisitor {
        type Value = ProtocolVersion;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str(r#"4 or 5 as an integer, or the special string value "auto""#)
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            match v {
                4 => Ok(ProtocolVersion::V4),
                5 => Ok(ProtocolVersion::V5),
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
                "auto" => Ok(ProtocolVersion::v4_upgrading_to_v5_with_default_tries()),
                _ => Err(E::custom(r#"Version must be 4, 5 or "auto""#)),
            }
        }
    }

    deserializer.deserialize_any(ProtocolVersionVisitor)
}

fn default_ntp_version() -> ProtocolVersion {
    ProtocolVersion::V4
}

#[derive(Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct StandardSource {
    pub address: NtpAddress,
    #[serde(
        default = "default_ntp_version",
        deserialize_with = "deserialize_ntp_version"
    )]
    pub ntp_version: ProtocolVersion,
}

#[derive(Debug, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NtsSourceConfig {
    pub address: NtsKeAddress,
    #[serde(
        deserialize_with = "deserialize_certificate_authorities",
        default = "default_certificate_authorities",
        rename = "certificate-authority"
    )]
    pub certificate_authorities: Arc<[Certificate]>,
    #[serde(
        default = "default_ntp_version",
        deserialize_with = "deserialize_ntp_version"
    )]
    pub ntp_version: ProtocolVersion,
}

fn deserialize_certificate_authorities<'de, D>(
    deserializer: D,
) -> Result<Arc<[Certificate]>, D::Error>
where
    D: Deserializer<'de>,
{
    let certificate_path: PathBuf = PathBuf::deserialize(deserializer)?;
    match certificates_from_file(&certificate_path) {
        Ok(certificates) => Ok(Arc::from(certificates)),
        Err(io_error) => {
            let msg =
                format!("error while parsing certificate file {certificate_path:?}: {io_error:?}");
            Err(de::Error::custom(msg))
        }
    }
}

fn default_certificate_authorities() -> Arc<[Certificate]> {
    Arc::from([])
}

#[derive(Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PoolSourceConfig {
    #[serde(rename = "address")]
    pub addr: NtpAddress,
    #[serde(default = "max_sources_default")]
    pub count: usize,
    #[serde(default)]
    pub ignore: Vec<IpAddr>,
    #[serde(
        default = "default_ntp_version",
        deserialize_with = "deserialize_ntp_version"
    )]
    pub ntp_version: ProtocolVersion,
}

fn max_sources_default() -> usize {
    4
}

#[cfg(feature = "unstable_nts-pool")]
#[derive(Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NtsPoolSourceConfig {
    #[serde(rename = "address")]
    pub addr: NtsKeAddress,
    #[serde(
        deserialize_with = "deserialize_certificate_authorities",
        default = "default_certificate_authorities",
        rename = "certificate-authority"
    )]
    pub certificate_authorities: Arc<[Certificate]>,
    #[serde(default = "max_sources_default")]
    pub count: usize,
    #[serde(
        default = "default_ntp_version",
        deserialize_with = "deserialize_ntp_version"
    )]
    pub ntp_version: ProtocolVersion,
}

#[derive(Debug, PartialEq, Clone)]
pub struct SockSourceConfig {
    pub path: PathBuf,
    pub precision: f64,
}

impl<'de> Deserialize<'de> for SockSourceConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Path,
            Precision,
            MeasurementNoiseEstimate,
        }

        struct SockSourceConfigVisitor;

        impl<'de> serde::de::Visitor<'de> for SockSourceConfigVisitor {
            type Value = SockSourceConfig;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("struct SockSourceConfig")
            }

            fn visit_map<V>(self, mut map: V) -> Result<SockSourceConfig, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut path = None;
                let mut precision = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Path => {
                            if path.is_some() {
                                return Err(de::Error::duplicate_field("path"));
                            }
                            path = Some(map.next_value()?);
                        }
                        Field::MeasurementNoiseEstimate => {
                            tracing::warn!(
                                "The measurement_noise_estimate field is deprecated. Please switch to using the precision field"
                            );
                            if precision.is_some() {
                                return Err(de::Error::duplicate_field(
                                    "measurement_noise_estimate",
                                ));
                            }
                            let variance: f64 = map.next_value()?;
                            if variance.partial_cmp(&0.0) != Some(core::cmp::Ordering::Greater) {
                                return Err(de::Error::invalid_value(
                                    serde::de::Unexpected::Float(variance),
                                    &"measurement_noise_estimate should be positive",
                                ));
                            }
                            precision = Some(variance.sqrt());
                        }
                        Field::Precision => {
                            if precision.is_some() {
                                return Err(de::Error::duplicate_field("precision"));
                            }
                            let precision_raw: f64 = map.next_value()?;
                            if precision_raw.partial_cmp(&0.0) != Some(core::cmp::Ordering::Greater)
                            {
                                return Err(de::Error::invalid_value(
                                    serde::de::Unexpected::Float(precision_raw),
                                    &"measurement_noise_estimate should be positive",
                                ));
                            }
                            precision = Some(precision_raw);
                        }
                    }
                }
                let path = path.ok_or_else(|| serde::de::Error::missing_field("path"))?;
                let precision =
                    precision.ok_or_else(|| serde::de::Error::missing_field("precision"))?;
                Ok(SockSourceConfig { path, precision })
            }
        }

        const FIELDS: &[&str] = &["path", "precision", "measurement_noise_estimate"];
        deserializer.deserialize_struct("SockSourceConfig", FIELDS, SockSourceConfigVisitor)
    }
}

#[derive(Deserialize, Debug, PartialEq, Eq, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct PartialPollIntervalLimits {
    pub min: Option<PollInterval>,
    pub max: Option<PollInterval>,
}

#[derive(Deserialize, Debug, PartialEq, Eq, Clone, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PartialSourceConfig {
    /// Minima and maxima for the poll interval of clients
    #[serde(default)]
    pub poll_interval_limits: PartialPollIntervalLimits,

    /// Initial poll interval of the system
    pub initial_poll_interval: Option<PollInterval>,
}

impl PartialSourceConfig {
    pub fn with_defaults(self, defaults: SourceConfig) -> SourceConfig {
        SourceConfig {
            poll_interval_limits: PollIntervalLimits {
                min: self
                    .poll_interval_limits
                    .min
                    .unwrap_or(defaults.poll_interval_limits.min),
                max: self
                    .poll_interval_limits
                    .max
                    .unwrap_or(defaults.poll_interval_limits.max),
            },
            initial_poll_interval: self
                .initial_poll_interval
                .unwrap_or(defaults.initial_poll_interval),
        }
    }
}

#[derive(Deserialize, Debug, PartialEq, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct FlattenedPair<T, U> {
    #[serde(flatten)]
    pub first: T,
    #[serde(flatten)]
    pub second: U,
}

#[derive(Debug, PartialEq, Clone)]
pub struct PpsSourceConfig {
    pub path: PathBuf,
    pub precision: f64,
    pub period: f64,
}

#[cfg(feature = "ptp")]
#[derive(Debug, PartialEq, Clone)]
pub struct PtpSourceConfig {
    pub delay: f64,
    pub interval: PollInterval,
    pub path: PathBuf,
    pub precision: f64,
    pub stratum: u8,
}

#[cfg(feature = "ptp")]
impl<'de> Deserialize<'de> for PtpSourceConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Delay,
            Interval,
            Path,
            Precision,
            Stratum,
        }

        struct PtpSourceConfigVisitor;

        impl<'de> serde::de::Visitor<'de> for PtpSourceConfigVisitor {
            type Value = PtpSourceConfig;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("struct PtpSourceConfig")
            }

            fn visit_map<V>(self, mut map: V) -> Result<PtpSourceConfig, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut delay = None;
                let mut interval = None;
                let mut path = None;
                let mut precision = None;
                let mut stratum = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Delay => {
                            if delay.is_some() {
                                return Err(de::Error::duplicate_field("delay"));
                            }
                            let delay_raw: f64 = map.next_value()?;
                            if delay_raw.partial_cmp(&0.0) != Some(core::cmp::Ordering::Greater) || delay_raw >= 16.0 {
                                return Err(de::Error::invalid_value(
                                    serde::de::Unexpected::Float(delay_raw),
                                    &"delay should be positive and less than 16",
                                ));
                            }
                            delay = Some(delay_raw);
                        }
                        Field::Interval => {
                            if interval.is_some() {
                                return Err(de::Error::duplicate_field("interval"));
                            }
                            let interval_value: PollInterval = map.next_value()?;
                            if interval_value.as_log() < 0 || interval_value.as_log() > 17 {
                                return Err(de::Error::invalid_value(
                                    serde::de::Unexpected::Signed(interval_value.as_log() as i64),
                                    &"interval should be between 0 and 17",
                                ));
                            }
                            interval = Some(interval_value);
                        }
                        Field::Path => {
                            if path.is_some() {
                                return Err(de::Error::duplicate_field("path"));
                            }
                            path = Some(map.next_value()?);
                        }
                        Field::Precision => {
                            if precision.is_some() {
                                return Err(de::Error::duplicate_field("precision"));
                            }
                            let precision_raw: f64 = map.next_value()?;
                            if precision_raw.partial_cmp(&0.0) != Some(core::cmp::Ordering::Greater)
                            {
                                return Err(de::Error::invalid_value(
                                    serde::de::Unexpected::Float(precision_raw),
                                    &"precision should be positive",
                                ));
                            }
                            precision = Some(precision_raw);
                        }
                        Field::Stratum => {
                            if stratum.is_some() {
                                return Err(de::Error::duplicate_field("stratum"));
                            }
                            let stratum_raw: u8 = map.next_value()?;
                            if stratum_raw >= 16 {
                                return Err(de::Error::invalid_value(
                                    serde::de::Unexpected::Unsigned(stratum_raw as u64),
                                    &"stratum should be less than 16",
                                ));
                            }
                            stratum = Some(stratum_raw);
                        }
                    }
                }
                let delay = delay.unwrap_or(0.0);
                let interval = interval.unwrap_or(PollInterval::from_byte(0)); // Default to 1 second
                let path = path.ok_or_else(|| serde::de::Error::missing_field("path"))?;
                let precision = precision.unwrap_or(0.000000001); // Default to 1 nanosecond
                let stratum = stratum.unwrap_or(0);
                Ok(PtpSourceConfig {
                    delay,
                    interval,
                    path,
                    precision,
                    stratum,
                })
            }
        }

        const FIELDS: &[&str] = &["delay", "interval", "path", "precision", "stratum"];
        deserializer.deserialize_struct("PtpSourceConfig", FIELDS, PtpSourceConfigVisitor)
    }
}

impl<'de> Deserialize<'de> for PpsSourceConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Path,
            Precision,
            MeasurementNoiseEstimate,
            Period,
        }

        struct PpsSourceConfigVisitor;

        impl<'de> serde::de::Visitor<'de> for PpsSourceConfigVisitor {
            type Value = PpsSourceConfig;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("struct PpsSourceConfig")
            }

            fn visit_map<V>(self, mut map: V) -> Result<PpsSourceConfig, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut path = None;
                let mut precision = None;
                let mut period = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Path => {
                            if path.is_some() {
                                return Err(de::Error::duplicate_field("path"));
                            }
                            path = Some(map.next_value()?);
                        }
                        Field::MeasurementNoiseEstimate => {
                            tracing::warn!(
                                "The measurement_noise_estimate field is deprecated. Please switch to using the precision field"
                            );
                            if precision.is_some() {
                                return Err(de::Error::duplicate_field(
                                    "measurement_noise_estimate",
                                ));
                            }
                            let variance: f64 = map.next_value()?;
                            if variance.partial_cmp(&0.0) != Some(core::cmp::Ordering::Greater) {
                                return Err(de::Error::invalid_value(
                                    serde::de::Unexpected::Float(variance),
                                    &"measurement_noise_estimate should be positive",
                                ));
                            }
                            precision = Some(variance.sqrt());
                        }
                        Field::Precision => {
                            if precision.is_some() {
                                return Err(de::Error::duplicate_field("precision"));
                            }
                            let precision_raw: f64 = map.next_value()?;
                            if precision_raw.partial_cmp(&0.0) != Some(core::cmp::Ordering::Greater)
                            {
                                return Err(de::Error::invalid_value(
                                    serde::de::Unexpected::Float(precision_raw),
                                    &"measurement_noise_estimate should be positive",
                                ));
                            }
                            precision = Some(precision_raw);
                        }
                        Field::Period => {
                            if period.is_some() {
                                return Err(de::Error::duplicate_field("period"));
                            }
                            let period_raw: f64 = map.next_value()?;
                            if period_raw.partial_cmp(&0.0) != Some(core::cmp::Ordering::Greater) {
                                return Err(de::Error::invalid_value(
                                    serde::de::Unexpected::Float(period_raw),
                                    &"period should be positive",
                                ));
                            }
                            period = Some(period_raw);
                        }
                    }
                }
                let path = path.ok_or_else(|| serde::de::Error::missing_field("path"))?;
                let precision =
                    precision.ok_or_else(|| serde::de::Error::missing_field("precision"))?;
                let period = period.unwrap_or(1.0);
                Ok(PpsSourceConfig {
                    path,
                    precision,
                    period,
                })
            }
        }

        const FIELDS: &[&str] = &["path", "precision", "measurement_noise_estimate"];
        deserializer.deserialize_struct("PpsSourceConfig", FIELDS, PpsSourceConfigVisitor)
    }
}

#[derive(Debug, Deserialize, PartialEq, Clone)]
#[serde(tag = "mode")]
pub enum NtpSourceConfig {
    #[serde(rename = "server")]
    Standard(FlattenedPair<StandardSource, PartialSourceConfig>),
    #[serde(rename = "nts")]
    Nts(FlattenedPair<NtsSourceConfig, PartialSourceConfig>),
    #[serde(rename = "pool")]
    Pool(FlattenedPair<PoolSourceConfig, PartialSourceConfig>),
    #[cfg(feature = "unstable_nts-pool")]
    #[serde(rename = "nts-pool")]
    NtsPool(FlattenedPair<NtsPoolSourceConfig, PartialSourceConfig>),
    #[serde(rename = "sock")]
    Sock(SockSourceConfig),
    #[cfg(feature = "pps")]
    #[serde(rename = "pps")]
    Pps(PpsSourceConfig),
    #[cfg(feature = "ptp")]
    #[serde(rename = "ptp")]
    Ptp(PtpSourceConfig),
}

/// A normalized address has a host and a port part. However, the host may be
/// invalid, we didn't yet perform a DNS lookup.
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NormalizedAddress {
    pub(crate) server_name: String,
    pub(crate) port: u16,

    /// Used to inject socket address into the DNS lookup result
    #[cfg(test)]
    hardcoded_dns_resolve: HardcodedDnsResolve,
}

impl Eq for NormalizedAddress {}

impl PartialEq for NormalizedAddress {
    fn eq(&self, other: &Self) -> bool {
        self.server_name == other.server_name && self.port == other.port
    }
}

#[derive(Deserialize, Debug, Clone, Default)]
struct HardcodedDnsResolve {
    #[cfg_attr(not(test), allow(unused))]
    #[serde(skip)]
    addresses: Arc<Mutex<Vec<SocketAddr>>>,
}

impl From<Vec<SocketAddr>> for HardcodedDnsResolve {
    fn from(value: Vec<SocketAddr>) -> Self {
        Self {
            addresses: Arc::new(Mutex::new(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpAddress(pub NormalizedAddress);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtsKeAddress(pub NormalizedAddress);

impl<'de> Deserialize<'de> for NtpAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(NormalizedAddress::from_string_ntp(s)
            .map_err(serde::de::Error::custom)?
            .into())
    }
}

impl<'de> Deserialize<'de> for NtsKeAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(NtsKeAddress(
            NormalizedAddress::from_string_nts_ke(s).map_err(serde::de::Error::custom)?,
        ))
    }
}

impl From<NormalizedAddress> for NtpAddress {
    fn from(addr: NormalizedAddress) -> Self {
        Self(addr)
    }
}

impl From<NormalizedAddress> for NtsKeAddress {
    fn from(addr: NormalizedAddress) -> Self {
        Self(addr)
    }
}

impl Deref for NtsKeAddress {
    type Target = NormalizedAddress;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for NtpAddress {
    type Target = NormalizedAddress;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl NormalizedAddress {
    const NTP_DEFAULT_PORT: u16 = 123;
    const NTS_KE_DEFAULT_PORT: u16 = 4460;

    /// Specifically, this adds the `:123` port if no port is specified
    pub(crate) fn from_string_ntp(address: String) -> std::io::Result<Self> {
        let (server_name, port) = Self::from_string_help(address, Self::NTP_DEFAULT_PORT)?;

        Ok(Self {
            server_name,
            port,

            #[cfg(test)]
            hardcoded_dns_resolve: HardcodedDnsResolve::default(),
        })
    }

    /// Specifically, this adds the `:4460` port if no port is specified
    fn from_string_nts_ke(address: String) -> std::io::Result<Self> {
        let (server_name, port) = Self::from_string_help(address, Self::NTS_KE_DEFAULT_PORT)?;

        Ok(Self {
            server_name,
            port,

            #[cfg(test)]
            hardcoded_dns_resolve: HardcodedDnsResolve::default(),
        })
    }

    fn from_string_help(address: String, default_port: u16) -> std::io::Result<(String, u16)> {
        if address.split(':').count() > 2 {
            // IPv6, try to parse it as such
            match address.parse::<SocketAddr>() {
                Ok(socket_addr) => Ok((socket_addr.ip().to_string(), socket_addr.port())),
                Err(e) => {
                    // Could be because of no port, add one and see
                    let address_with_port = format!("[{address}]:{default_port}");
                    if let Ok(socket_addr) = address_with_port.parse::<SocketAddr>() {
                        Ok((socket_addr.ip().to_string(), socket_addr.port()))
                    } else {
                        Err(std::io::Error::other(e))
                    }
                }
            }
        } else if let Some((server_name, port)) = address.split_once(':') {
            // Not ipv6, and we seem to have a port. We cant reasonably
            // check whether the host is valid, but at least check that
            // the port is.
            match port.parse::<u16>() {
                Ok(port) => Ok((server_name.to_string(), port)),
                Err(e) => Err(std::io::Error::other(e)),
            }
        } else {
            // Not ipv6 and no port. As we cant reasonably check host
            // so just append a port
            Ok((address, default_port))
        }
    }

    #[cfg(test)]
    pub(crate) fn new_unchecked(server_name: &str, port: u16) -> Self {
        Self {
            server_name: server_name.to_string(),
            port,

            #[cfg(test)]
            hardcoded_dns_resolve: HardcodedDnsResolve::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_hardcoded_dns(
        server_name: &str,
        port: u16,
        hardcoded_dns_resolve: Vec<SocketAddr>,
    ) -> Self {
        Self {
            server_name: server_name.to_string(),
            port,
            hardcoded_dns_resolve: HardcodedDnsResolve::from(hardcoded_dns_resolve),
        }
    }

    #[cfg(not(test))]
    pub async fn lookup_host(&self) -> std::io::Result<impl Iterator<Item = SocketAddr> + '_> {
        tokio::net::lookup_host((self.server_name.as_str(), self.port)).await
    }

    #[cfg(test)]
    pub async fn lookup_host(&self) -> std::io::Result<impl Iterator<Item = SocketAddr> + '_> {
        // We don't want to spam a real DNS server during testing. This is an attempt to randomize
        // the returned addresses somewhat.
        let mut addresses = self.hardcoded_dns_resolve.addresses.lock().unwrap();

        if let Some(last) = addresses.pop() {
            addresses.insert(0, last);
        }

        let addresses = addresses.to_vec();

        Ok(addresses.into_iter())
    }
}

impl std::fmt::Display for NormalizedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.server_name.contains(':') {
            write!(f, "[{}]:{}", self.server_name, self.port)
        } else {
            write!(f, "{}:{}", self.server_name, self.port)
        }
    }
}

impl TryFrom<&str> for StandardSource {
    type Error = std::io::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            address: NormalizedAddress::from_string_ntp(value.to_string())?.into(),
            ntp_version: default_ntp_version(),
        })
    }
}

impl<'a> TryFrom<&'a str> for NtpSourceConfig {
    type Error = std::io::Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        StandardSource::try_from(value).map(|first| {
            Self::Standard(FlattenedPair {
                first,
                second: Default::default(),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize, Debug)]
    struct TestConfig {
        source: NtpSourceConfig,
    }

    fn source_addr(config: &NtpSourceConfig) -> String {
        match config {
            NtpSourceConfig::Standard(c) => c.first.address.to_string(),
            NtpSourceConfig::Nts(c) => c.first.address.to_string(),
            NtpSourceConfig::Pool(c) => c.first.addr.to_string(),
            #[cfg(feature = "unstable_nts-pool")]
            NtpSourceConfig::NtsPool(c) => c.first.addr.to_string(),
            NtpSourceConfig::Sock(_c) => "".to_string(),
            #[cfg(feature = "pps")]
            NtpSourceConfig::Pps(_c) => "".to_string(),
            #[cfg(feature = "ptp")]
            NtpSourceConfig::Ptp(_c) => "".to_string(),
        }
    }

    #[test]
    fn test_deserialize_source() {
        let test: TestConfig = toml::from_str(
            r#"
            [source]
            mode = "server"
            address = "example.com"
            "#,
        )
        .unwrap();
        assert_eq!(source_addr(&test.source), "example.com:123");
        assert!(matches!(test.source, NtpSourceConfig::Standard(_)));

        let test: TestConfig = toml::from_str(
            r#"
            [source]
            mode = "server"
            address = "example.com:5678"
            "#,
        )
        .unwrap();
        assert_eq!(source_addr(&test.source), "example.com:5678");
        assert!(matches!(test.source, NtpSourceConfig::Standard(_)));

        let test: TestConfig = toml::from_str(
            r#"
            [source]
            mode = "server"
            address = "example.com"
            "#,
        )
        .unwrap();
        assert_eq!(source_addr(&test.source), "example.com:123");
        assert!(matches!(test.source, NtpSourceConfig::Standard(_)));

        let test: TestConfig = toml::from_str(
            r#"
            [source]
            address = "example.com"
            mode = "pool"
            "#,
        )
        .unwrap();
        assert!(matches!(test.source, NtpSourceConfig::Pool(_)));
        assert_eq!(source_addr(&test.source), "example.com:123");
        if let NtpSourceConfig::Pool(config) = test.source {
            assert_eq!(config.first.count, 4);
        }

        let test: TestConfig = toml::from_str(
            r#"
            [source]
            address = "example.com"
            mode = "pool"
            count = 42
            "#,
        )
        .unwrap();
        assert!(matches!(test.source, NtpSourceConfig::Pool(_)));
        assert_eq!(source_addr(&test.source), "example.com:123");
        if let NtpSourceConfig::Pool(config) = test.source {
            assert_eq!(config.first.count, 42);
        }

        let test: TestConfig = toml::from_str(
            r#"
            [source]
            address = "example.com"
            mode = "nts"
            "#,
        )
        .unwrap();
        assert!(matches!(test.source, NtpSourceConfig::Nts(_)));
        assert_eq!(source_addr(&test.source), "example.com:4460");

        #[cfg(feature = "unstable_nts-pool")]
        {
            let test: TestConfig = toml::from_str(
                r#"
            [source]
            address = "example.com"
            mode = "nts-pool"
            "#,
            )
            .unwrap();
            assert!(matches!(test.source, NtpSourceConfig::NtsPool(_)));
            assert_eq!(source_addr(&test.source), "example.com:4460");
        }
    }

    #[test]
    fn test_deserialize_source_ntp_version() {
        let test: TestConfig = toml::from_str(
            r#"
            [source]
            address = "example.com"
            mode = "server"
            ntp-version = "auto"
            "#,
        )
        .unwrap();
        let NtpSourceConfig::Standard(source) = test.source else {
            panic!("Invalid source type");
        };
        assert_eq!(
            source.first.ntp_version,
            ProtocolVersion::v4_upgrading_to_v5_with_default_tries()
        );

        let test: TestConfig = toml::from_str(
            r#"
            [source]
            address = "example.com"
            mode = "pool"
            ntp-version = 5
            "#,
        )
        .unwrap();
        let NtpSourceConfig::Pool(source) = test.source else {
            panic!("Invalid source type");
        };
        assert_eq!(source.first.ntp_version, ProtocolVersion::V5);

        let test: TestConfig = toml::from_str(
            r#"
            [source]
            address = "example.com"
            mode = "server"
            ntp-version = 4
            "#,
        )
        .unwrap();
        let NtpSourceConfig::Standard(source) = test.source else {
            panic!("Invalid source type");
        };
        assert_eq!(source.first.ntp_version, ProtocolVersion::V4);

        let test: TestConfig = toml::from_str(
            r#"
            [source]
            address = "example.com"
            mode = "nts"
            "#,
        )
        .unwrap();
        let NtpSourceConfig::Nts(source) = test.source else {
            panic!("Invalid source type");
        };
        assert_eq!(source.first.ntp_version, ProtocolVersion::V4);
    }

    #[test]
    fn test_deserialize_source_pem_certificate() {
        let contents = include_bytes!("../../../testdata/certificates/nos-nl.pem");
        let path = std::env::temp_dir().join("nos-nl.pem");
        std::fs::write(&path, contents).unwrap();

        let test: TestConfig = toml::from_str(&format!(
            r#"
                [source]
                address = "example.com"
                certificate-authority = "{}"
                mode = "nts"
                "#,
            path.display()
        ))
        .unwrap();
        assert!(matches!(test.source, NtpSourceConfig::Nts(_)));
        assert_eq!(source_addr(&test.source), "example.com:4460");
    }

    #[test]
    fn test_source_from_string() {
        let source = NtpSourceConfig::try_from("example.com").unwrap();
        assert_eq!(source_addr(&source), "example.com:123");
        assert!(matches!(source, NtpSourceConfig::Standard(_)));

        let source = NtpSourceConfig::try_from("example.com:5678").unwrap();
        assert_eq!(source_addr(&source), "example.com:5678");
        assert!(matches!(source, NtpSourceConfig::Standard(_)));
    }

    #[test]
    fn test_source_config_parsing() {
        let test: Result<TestConfig, _> = toml::from_str(
            r#"
                [source]
                mode = "server"
                address = "example.com"
                initial-poll-interval = 7
            "#,
        );
        assert!(test.is_ok());

        let test2: Result<TestConfig, _> = toml::from_str(
            r#"
                [source]
                mode = "server"
                address = "example.com"
                does-not-exist = 7
            "#,
        );
        assert!(test2.is_err());
    }

    #[test]
    fn test_sock_config_parsing() {
        let TestConfig {
            source: NtpSourceConfig::Sock(test),
        } = toml::from_str(
            r#"
                [source]
                mode = "sock"
                path = "/test/path"
                measurement_noise_estimate = 0.0625
            "#,
        )
        .unwrap()
        else {
            panic!("Unexpected source type");
        };
        assert_eq!(test.precision, 0.25);

        let TestConfig {
            source: NtpSourceConfig::Sock(test),
        } = toml::from_str(
            r#"
                [source]
                mode = "sock"
                path = "/test/path"
                precision = 0.25
            "#,
        )
        .unwrap()
        else {
            panic!("Unexpected source type");
        };
        assert_eq!(test.precision, 0.25);

        let test: Result<TestConfig, _> = toml::from_str(
            r#"
                [source]
                mode = "sock"
                path = "/test/path"
                precision = 0.25
                measurement_noise_estimate = 0.0625
            "#,
        );
        assert!(test.is_err());

        let test: Result<TestConfig, _> = toml::from_str(
            r#"
                [source]
                mode = "sock"
                path = "/test/path"
            "#,
        );
        assert!(test.is_err());

        let test: Result<TestConfig, _> = toml::from_str(
            r#"
                [source]
                mode = "sock"
                precision = 0.25
            "#,
        );
        assert!(test.is_err());

        let test: Result<TestConfig, _> = toml::from_str(
            r#"
                [source]
                mode = "sock"
                path = "/test/path"
                precision = 0.25
                unknown_field = 5
            "#,
        );
        assert!(test.is_err());

        let test: Result<TestConfig, _> = toml::from_str(
            r#"
                [source]
                mode = "sock"
                path = "/test/path"
                precision = -0.25
            "#,
        );
        assert!(test.is_err());

        let test: Result<TestConfig, _> = toml::from_str(
            r#"
                [source]
                mode = "sock"
                path = "/test/path"
                measurement_noise_estimate = -0.0625
            "#,
        );
        assert!(test.is_err());

        let test: Result<TestConfig, _> = toml::from_str(
            r#"
                [source]
                mode = "sock"
                path = "/test/path"
                precision = 0.0
            "#,
        );
        assert!(test.is_err());

        let test: Result<TestConfig, _> = toml::from_str(
            r#"
                [source]
                mode = "sock"
                path = "/test/path"
                measurement_noise_estimate = 0.0
            "#,
        );
        assert!(test.is_err());
    }

    #[cfg(feature = "pps")]
    #[test]
    fn test_pps_config_parsing() {
        let TestConfig {
            source: NtpSourceConfig::Pps(test),
        } = toml::from_str(
            r#"
            [source]
            mode = "pps"
            path = "/test/path"
            precision = 0.25
            period = 1.5
            "#,
        )
        .unwrap()
        else {
            panic!("Unexpected source type");
        };
        assert_eq!(test.precision, 0.25);
        assert_eq!(test.period, 1.5);

        let TestConfig {
            source: NtpSourceConfig::Pps(test),
        } = toml::from_str(
            r#"
            [source]
            mode = "pps"
            path = "/test/path"
            measurement_noise_estimate = 0.0625
            "#,
        )
        .unwrap()
        else {
            panic!("Unexpected source type");
        };
        assert_eq!(test.precision, 0.25);
        assert_eq!(test.period, 1.0);

        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "pps"
            path = "/test/path"
            precision = 0.25
            measurement_noise_estimate = 0.0625
            "#,
        );
        assert!(test.is_err());

        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "pps"
            path = "/test/path"
            "#,
        );
        assert!(test.is_err());

        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "pps"
            path = "/test/path"
            precision = 0.25
            unknown_field = 5
            "#,
        );
        assert!(test.is_err());

        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "pps"
            path = "/test/path"
            precision = -0.25
            "#,
        );
        assert!(test.is_err());

        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "pps"
            path = "/test/path"
            measurement_noise_estimate = -0.0625
            "#,
        );
        assert!(test.is_err());

        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "pps"
            path = "/test/path"
            precision = -0.25
            "#,
        );
        assert!(test.is_err());

        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "pps"
            path = "/test/path"
            precision = 0.25
            period = -0.5
            "#,
        );
        assert!(test.is_err());

        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "pps"
            path = "/test/path"
            measurement_noise_estimate = 0.0
            "#,
        );
        assert!(test.is_err());

        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "pps"
            path = "/test/path"
            precision = 0.0
            "#,
        );
        assert!(test.is_err());

        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "pps"
            path = "/test/path"
            precision = 0.25
            period = 0.0
            "#,
        );
        assert!(test.is_err());
    }

    #[cfg(feature = "ptp")]
    #[test]
    fn test_ptp_config_parsing() {
        let TestConfig {
            source: NtpSourceConfig::Ptp(test),
        } = toml::from_str(
            r#"
            [source]
            interval = 1
            mode = "ptp"
            path = "/dev/ptp0"
            precision = 0.000001
            "#,
        )
        .unwrap()
        else {
            panic!("Unexpected source type");
        };
        assert_eq!(test.delay, 0.0);
        assert_eq!(test.interval, ntp_proto::PollInterval::from_byte(1));
        assert_eq!(test.path, PathBuf::from("/dev/ptp0"));
        assert_eq!(test.precision, 0.000001);
        assert_eq!(test.stratum, 0);

        // Test with default interval
        let TestConfig {
            source: NtpSourceConfig::Ptp(test),
        } = toml::from_str(
            r#"
            [source]
            mode = "ptp"
            path = "/dev/ptp1"
            precision = 0.000005
            "#,
        )
        .unwrap()
        else {
            panic!("Unexpected source type");
        };
        assert_eq!(test.interval, ntp_proto::PollInterval::from_byte(0)); // Default interval
        assert_eq!(test.path, PathBuf::from("/dev/ptp1"));
        assert_eq!(test.precision, 0.000005);

        // Test validation - missing path should fail
        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "ptp"
            precision = 0.000001
            "#,
        );
        assert!(test.is_err());

        // Test with default precision (1 nanosecond)
        let TestConfig {
            source: NtpSourceConfig::Ptp(test),
        } = toml::from_str(
            r#"
            [source]
            mode = "ptp"
            path = "/dev/ptp0"
            "#,
        )
        .unwrap()
        else {
            panic!("Unexpected source type");
        };
        assert_eq!(test.interval, ntp_proto::PollInterval::from_byte(0)); // Default interval
        assert_eq!(test.path, PathBuf::from("/dev/ptp0"));
        assert_eq!(test.precision, 0.000000001); // Default precision (1 nanosecond)

        // Test validation - negative precision should fail
        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "ptp"
            path = "/dev/ptp0"
            precision = -0.000001
            "#,
        );
        assert!(test.is_err());

        // Test validation - negative interval should fail
        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "ptp"
            path = "/dev/ptp0"
            precision = 0.000001
            interval = -1
            "#,
        );
        assert!(test.is_err());

        // Test validation - zero precision should fail
        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "ptp"
            path = "/dev/ptp0"
            precision = 0.0
            "#,
        );
        assert!(test.is_err());

        // Test validation - interval too high should fail
        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            interval = 100
            mode = "ptp"
            path = "/dev/ptp0"
            precision = 0.000001
            "#,
        );
        assert!(test.is_err());

        // Test validation - unknown field should fail
        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "ptp"
            path = "/dev/ptp0"
            precision = 0.000001
            unknown_field = 5
            "#,
        );
        assert!(test.is_err());

        // Test validation - stratum >= 16 should fail
        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "ptp"
            path = "/dev/ptp0"
            stratum = 16
            "#,
        );
        assert!(test.is_err());

        // Test validation - non-integral stratum should fail
        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "ptp"
            path = "/dev/ptp0"
            stratum = 4.972
            "#,
        );
        assert!(test.is_err());

        // Test validation - non-numeric stratum should fail
        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "ptp"
            path = "/dev/ptp0"
            stratum = teststratum
            "#,
        );
        assert!(test.is_err());

        // Test validation - stratum < 0 should fail
        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "ptp"
            path = "/dev/ptp0"
            stratum = -3
            "#,
        );
        assert!(test.is_err());

        // Test validation - negative delay should fail
        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "ptp"
            path = "/dev/ptp0"
            delay = -1.0
            "#,
        );
        assert!(test.is_err());

        // Test validation - delay >= 16 should fail
        let test: Result<TestConfig, _> = toml::from_str(
            r#"
            [source]
            mode = "ptp"
            path = "/dev/ptp0"
            delay = 16.0
            "#,
        );
        assert!(test.is_err());
    }

    #[test]
    fn test_normalize_addr() {
        let addr = NormalizedAddress::from_string_ntp("[::1]:456".into()).unwrap();
        assert_eq!(addr.to_string(), "[::1]:456");
        let addr = NormalizedAddress::from_string_ntp("::1".into()).unwrap();
        assert_eq!(addr.to_string(), "[::1]:123");
        assert!(NormalizedAddress::from_string_ntp(":some:invalid:1".into()).is_err());
        let addr = NormalizedAddress::from_string_ntp("127.0.0.1:456".into()).unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:456");
        let addr = NormalizedAddress::from_string_ntp("127.0.0.1".into()).unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:123");
        let addr = NormalizedAddress::from_string_ntp("1234567890.example.com".into()).unwrap();
        assert_eq!(addr.to_string(), "1234567890.example.com:123");
    }
}
