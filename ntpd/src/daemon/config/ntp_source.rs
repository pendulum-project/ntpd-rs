use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    ops::Deref,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use rustls::pki_types::CertificateDer;
use serde::{de, Deserialize, Deserializer};

use super::super::keyexchange::certificates_from_file;

#[derive(Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct StandardSource {
    pub address: NtpAddress,
}

#[derive(Deserialize, Debug, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct GpsConfigSource {
    pub address: String,
    pub measurement_noise: f64,
    pub baud_rate: u32,
}

#[derive(Deserialize, Debug, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct PpsConfigSource {
    pub address: String,
    pub measurement_noise: f64,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct NtsSourceConfig {
    pub address: NtsKeAddress,
    #[serde(
        deserialize_with = "deserialize_certificate_authorities",
        default = "default_certificate_authorities",
        rename = "certificate-authority"
    )]
    pub certificate_authorities: Arc<[CertificateDer<'static>]>,
}

fn deserialize_certificate_authorities<'de, D>(
    deserializer: D,
) -> Result<Arc<[CertificateDer<'static>]>, D::Error>
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

fn default_certificate_authorities() -> Arc<[CertificateDer<'static>]> {
    Arc::from([])
}

#[derive(Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct PoolSourceConfig {
    #[serde(rename = "address")]
    pub addr: NtpAddress,
    #[serde(default = "max_sources_default")]
    pub count: usize,
    #[serde(default)]
    pub ignore: Vec<IpAddr>,
}

fn max_sources_default() -> usize {
    4
}

#[cfg(feature = "unstable_nts-pool")]
#[derive(Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct NtsPoolSourceConfig {
    #[serde(rename = "address")]
    pub addr: NtsKeAddress,
    #[serde(
        deserialize_with = "deserialize_certificate_authorities",
        default = "default_certificate_authorities",
        rename = "certificate-authority"
    )]
    pub certificate_authorities: Arc<[CertificateDer<'static>]>,
    #[serde(default = "max_sources_default")]
    pub count: usize,
}

#[derive(Debug, Deserialize, PartialEq, Clone)]
#[serde(tag = "mode")]
pub enum NtpSourceConfig {
    #[serde(rename = "Gps")]
    Gps(GpsConfigSource),
    #[serde(rename = "Pps")]
    Pps(PpsConfigSource),
    #[serde(rename = "server")]
    Standard(StandardSource),
    #[serde(rename = "nts")]
    Nts(NtsSourceConfig),
    #[serde(rename = "pool")]
    Pool(PoolSourceConfig),
    #[cfg(feature = "unstable_nts-pool")]
    #[serde(rename = "nts-pool")]
    NtsPool(NtsPoolSourceConfig),
}

/// A normalized address has a host and a port part. However, the host may be
/// invalid, we didn't yet perform a DNS lookup.
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NormalizedAddress {
    pub(crate) server_name: String,
    pub(crate) port: u16,

    /// Used to inject socket addrs into the DNS lookup result
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
pub struct GpsPort(pub NormalizedAddress);

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
                Ok(socket_addr) => {
                    // strip off the port
                    let (server_name, _) = address.rsplit_once(':').unwrap();

                    Ok((server_name.to_string(), socket_addr.port()))
                }
                Err(e) => {
                    // Could be because of no port, add one and see
                    let address_with_port = format!("[{address}]:{default_port}");
                    if address_with_port.parse::<SocketAddr>().is_ok() {
                        Ok((format!("[{address}]"), default_port))
                    } else {
                        Err(std::io::Error::new(std::io::ErrorKind::Other, e))
                    }
                }
            }
        } else if let Some((server_name, port)) = address.split_once(':') {
            // Not ipv6, and we seem to have a port. We cant reasonably
            // check whether the host is valid, but at least check that
            // the port is.
            match port.parse::<u16>() {
                Ok(port) => Ok((server_name.to_string(), port)),
                Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
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
        write!(f, "{}:{}", self.server_name, self.port)
    }
}

impl TryFrom<&str> for StandardSource {
    type Error = std::io::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            address: NormalizedAddress::from_string_ntp(value.to_string())?.into(),
        })
    }
}

impl<'a> TryFrom<&'a str> for NtpSourceConfig {
    type Error = std::io::Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        StandardSource::try_from(value).map(Self::Standard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_addr(config: &NtpSourceConfig) -> String {
        match config {
            NtpSourceConfig::Standard(c) => c.address.to_string(),
            NtpSourceConfig::Nts(c) => c.address.to_string(),
            NtpSourceConfig::Pool(c) => c.addr.to_string(),
            NtpSourceConfig::Gps(c) => c.address.to_string(),
            NtpSourceConfig::Pps(c) => c.address.to_string(),
            #[cfg(feature = "unstable_nts-pool")]
            NtpSourceConfig::NtsPool(c) => c.addr.to_string(),
        }
    }

    #[test]
    fn test_deserialize_source() {
        #[derive(Deserialize, Debug)]
        struct TestConfig {
            source: NtpSourceConfig,
        }

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
        if let NtpSourceConfig::Pool(config) = test.source {
            assert_eq!(config.addr.to_string(), "example.com:123");
            assert_eq!(config.count, 4);
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
        if let NtpSourceConfig::Pool(config) = test.source {
            assert_eq!(config.addr.to_string(), "example.com:123");
            assert_eq!(config.count, 42);
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
        if let NtpSourceConfig::Nts(config) = test.source {
            assert_eq!(config.address.to_string(), "example.com:4460");
        }

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
            if let NtpSourceConfig::Nts(config) = test.source {
                assert_eq!(config.address.to_string(), "example.com:4460");
            }
        }
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
