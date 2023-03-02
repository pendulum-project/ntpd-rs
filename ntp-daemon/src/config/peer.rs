use std::{fmt, net::SocketAddr, path::PathBuf, sync::Arc};

use rustls::Certificate;
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer,
};

use crate::keyexchange::certificates_from_file;

#[derive(Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum PeerHostMode {
    #[serde(alias = "server")]
    Server,
    #[serde(alias = "nts-server")]
    NtsServer,
    #[serde(alias = "pool")]
    Pool,
}

impl Default for PeerHostMode {
    fn default() -> Self {
        PeerHostMode::Server
    }
}

#[derive(Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct StandardPeerConfig {
    pub addr: NormalizedAddress,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NtsPeerConfig {
    pub ke_addr: NormalizedAddress,
    pub certificates: Arc<[Certificate]>,
}

#[derive(Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct PoolPeerConfig {
    pub addr: NormalizedAddress,
    pub max_peers: usize,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PeerConfig {
    Standard(StandardPeerConfig),
    Nts(NtsPeerConfig),
    Pool(PoolPeerConfig),
    // Consul(ConsulPeerConfig),
}

impl PeerConfig {
    pub(crate) fn try_from_str(value: &str) -> Result<Self, std::io::Error> {
        Self::try_from(value)
    }
}

/// A normalized address has a host and a port part. However, the host may be
/// invalid, we didn't yet perform a DNS lookup.
#[derive(Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct NormalizedAddress {
    pub(crate) server_name: String,
    pub(crate) port: u16,

    /// Used to inject socket addrs into the DNS lookup result
    #[cfg(test)]
    hardcoded_dns_resolve: Vec<SocketAddr>,
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
            hardcoded_dns_resolve: vec![],
        })
    }

    /// Specifically, this adds the `:4460` port if no port is specified
    fn from_string_nts_ke(address: String) -> std::io::Result<Self> {
        let (server_name, port) = Self::from_string_help(address, Self::NTS_KE_DEFAULT_PORT)?;

        Ok(Self {
            server_name,
            port,

            #[cfg(test)]
            hardcoded_dns_resolve: vec![],
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
            hardcoded_dns_resolve: vec![],
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn with_hardcoded_dns(
        server_name: &str,
        port: u16,
        hardcoded_dns_resolve: Vec<SocketAddr>,
    ) -> Self {
        Self {
            server_name: server_name.to_string(),
            port,
            hardcoded_dns_resolve,
        }
    }

    #[cfg(not(test))]
    pub async fn lookup_host(&self) -> std::io::Result<impl Iterator<Item = SocketAddr> + '_> {
        tokio::net::lookup_host((self.server_name.as_str(), self.port)).await
    }

    #[cfg(test)]
    pub async fn lookup_host(&self) -> std::io::Result<impl Iterator<Item = SocketAddr> + '_> {
        let addresses = if !self.hardcoded_dns_resolve.is_empty() {
            self.hardcoded_dns_resolve.to_vec()
        } else {
            tokio::net::lookup_host((self.server_name.as_str(), self.port))
                .await?
                .collect()
        };

        Ok(addresses.into_iter())
    }
}

impl std::fmt::Display for NormalizedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.server_name, self.port)
    }
}

impl TryFrom<&str> for StandardPeerConfig {
    type Error = std::io::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            addr: NormalizedAddress::from_string_ntp(value.to_string())?,
        })
    }
}

impl<'a> TryFrom<&'a str> for PeerConfig {
    type Error = std::io::Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        StandardPeerConfig::try_from(value).map(Self::Standard)
    }
}

// We have a custom deserializer for peerconfig because we
// want to deserialize it from either a string or a map
impl<'de> Deserialize<'de> for PeerConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PeerConfigVisitor;

        impl<'de> Visitor<'de> for PeerConfigVisitor {
            type Value = PeerConfig;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("string or map")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<PeerConfig, E> {
                TryFrom::try_from(value).map_err(de::Error::custom)
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<PeerConfig, M::Error> {
                let mut ke_addr = None;
                let mut opt_certificate_path = None;
                let mut addr = None;
                let mut mode = None;
                let mut max_peers = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "addr" => {
                            if addr.is_some() {
                                return Err(de::Error::duplicate_field("addr"));
                            }
                            let raw: String = map.next_value()?;

                            let parsed_addr =
                                NormalizedAddress::from_string_ntp(raw.as_str().to_string())
                                    .map_err(de::Error::custom)?;

                            addr = Some(parsed_addr);
                        }
                        "ke-addr" => {
                            if ke_addr.is_some() {
                                return Err(de::Error::duplicate_field("ke_addr"));
                            }
                            let raw: String = map.next_value()?;

                            let parsed_addr =
                                NormalizedAddress::from_string_nts_ke(raw.as_str().to_string())
                                    .map_err(de::Error::custom)?;

                            ke_addr = Some(parsed_addr);
                        }
                        "certificate" => {
                            if opt_certificate_path.is_some() {
                                return Err(de::Error::duplicate_field("certificate"));
                            }
                            let raw: String = map.next_value()?;

                            opt_certificate_path = Some(PathBuf::from(raw));
                        }
                        "mode" => {
                            if mode.is_some() {
                                return Err(de::Error::duplicate_field("mode"));
                            }
                            mode = Some(map.next_value()?);
                        }
                        "max-peers" => {
                            if max_peers.is_some() {
                                return Err(de::Error::duplicate_field("max_peers"));
                            }
                            max_peers = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(de::Error::unknown_field(
                                key.as_str(),
                                &["addr", "ke-addr", "certificate", "mode", "max-peers"],
                            ));
                        }
                    }
                }

                let mode = mode.unwrap_or_default();

                let unknown_field =
                    |field, valid_fields| Err(de::Error::unknown_field(field, valid_fields));

                match mode {
                    PeerHostMode::Server => {
                        let addr = addr.ok_or_else(|| de::Error::missing_field("addr"))?;

                        let valid_fields = &["addr", "mode"];
                        if max_peers.is_some() {
                            unknown_field("max-peers", valid_fields)
                        } else if ke_addr.is_some() {
                            unknown_field("ke-addr", valid_fields)
                        } else if opt_certificate_path.is_some() {
                            unknown_field("certificate", valid_fields)
                        } else {
                            Ok(PeerConfig::Standard(StandardPeerConfig { addr }))
                        }
                    }
                    PeerHostMode::NtsServer => {
                        let ke_addr = ke_addr.ok_or_else(|| de::Error::missing_field("ke_addr"))?;

                        let valid_fields = &["mode", "ke-addr", "certificate"];
                        if max_peers.is_some() {
                            unknown_field("max-peers", valid_fields)
                        } else {
                            let certificates: Arc<[Certificate]> = if let Some(certificate_path) =
                                opt_certificate_path
                            {
                                match certificates_from_file(&certificate_path) {
                                    Ok(certificates) => Arc::from(certificates),
                                    Err(io_error) => {
                                        let msg = format!(
                                                "error while parsing certificate file {certificate_path:?}: {io_error:?}"
                                            );
                                        return Err(de::Error::custom(msg));
                                    }
                                }
                            } else {
                                Arc::from([])
                            };

                            Ok(PeerConfig::Nts(NtsPeerConfig {
                                ke_addr,
                                certificates,
                            }))
                        }
                    }
                    PeerHostMode::Pool => {
                        let addr = addr.ok_or_else(|| de::Error::missing_field("addr"))?;

                        let valid_fields = &["addr", "mode", "max-peers"];
                        if ke_addr.is_some() {
                            unknown_field("ke-addr", valid_fields)
                        } else if opt_certificate_path.is_some() {
                            unknown_field("certificate", valid_fields)
                        } else {
                            let max_peers = max_peers.unwrap_or(1);

                            Ok(PeerConfig::Pool(PoolPeerConfig { addr, max_peers }))
                        }
                    }
                }
            }
        }

        deserializer.deserialize_any(PeerConfigVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_addr(config: &PeerConfig) -> String {
        match config {
            PeerConfig::Standard(c) => c.addr.to_string(),
            PeerConfig::Nts(c) => c.ke_addr.to_string(),
            PeerConfig::Pool(c) => c.addr.to_string(),
        }
    }

    #[test]
    fn test_deserialize_peer() {
        #[derive(Deserialize, Debug)]
        struct TestConfig {
            peer: PeerConfig,
        }

        let test: TestConfig = toml::from_str("peer = \"example.com\"").unwrap();
        assert_eq!(peer_addr(&test.peer), "example.com:123");
        assert!(matches!(test.peer, PeerConfig::Standard(_)));

        let test: TestConfig = toml::from_str("peer = \"example.com:5678\"").unwrap();
        assert_eq!(peer_addr(&test.peer), "example.com:5678");
        assert!(matches!(test.peer, PeerConfig::Standard(_)));

        let test: TestConfig = toml::from_str("[peer]\naddr = \"example.com\"").unwrap();
        assert_eq!(peer_addr(&test.peer), "example.com:123");
        assert!(matches!(test.peer, PeerConfig::Standard(_)));

        let test: TestConfig = toml::from_str("[peer]\naddr = \"example.com:5678\"").unwrap();
        assert_eq!(peer_addr(&test.peer), "example.com:5678");
        assert!(matches!(test.peer, PeerConfig::Standard(_)));

        let test: TestConfig = toml::from_str(
            r#"
            [peer]
            addr = "example.com"
            mode = "Server"
            "#,
        )
        .unwrap();
        assert_eq!(peer_addr(&test.peer), "example.com:123");
        assert!(matches!(test.peer, PeerConfig::Standard(_)));

        let test: TestConfig = toml::from_str(
            r#"
            [peer]
            addr = "example.com"
            mode = "Pool"
            "#,
        )
        .unwrap();
        assert!(matches!(test.peer, PeerConfig::Pool(_)));
        if let PeerConfig::Pool(config) = test.peer {
            assert_eq!(config.addr.to_string(), "example.com:123");
            assert_eq!(config.max_peers, 1);
        }

        let test: TestConfig = toml::from_str(
            r#"
            [peer]
            addr = "example.com"
            mode = "Pool"
            max-peers = 42
            "#,
        )
        .unwrap();
        assert!(matches!(test.peer, PeerConfig::Pool(_)));
        if let PeerConfig::Pool(config) = test.peer {
            assert_eq!(config.addr.to_string(), "example.com:123");
            assert_eq!(config.max_peers, 42);
        }

        let test: TestConfig = toml::from_str(
            r#"
            [peer]
            ke-addr = "example.com"
            mode = "NtsServer"
            "#,
        )
        .unwrap();
        assert!(matches!(test.peer, PeerConfig::Nts(_)));
        if let PeerConfig::Nts(config) = test.peer {
            assert_eq!(config.ke_addr.to_string(), "example.com:4460");
        }
    }

    #[test]
    fn test_deserialize_peer_pem_certificate() {
        let contents = include_bytes!("../../testdata/certificates/nos-nl.pem");
        let path = std::env::temp_dir().join("nos-nl.pem");
        std::fs::write(&path, contents).unwrap();

        #[derive(Deserialize, Debug)]
        struct TestConfig {
            peer: PeerConfig,
        }

        let test: TestConfig = toml::from_str(&format!(
            r#"
                [peer]
                ke-addr = "example.com"
                certificate = "{}"
                mode = "NtsServer"
                "#,
            path.display()
        ))
        .unwrap();
        assert!(matches!(test.peer, PeerConfig::Nts(_)));
        if let PeerConfig::Nts(config) = test.peer {
            assert_eq!(config.ke_addr.to_string(), "example.com:4460");
        }
    }

    #[test]
    fn test_peer_from_string() {
        let peer = PeerConfig::try_from("example.com").unwrap();
        assert_eq!(peer_addr(&peer), "example.com:123");
        assert!(matches!(peer, PeerConfig::Standard(_)));

        let peer = PeerConfig::try_from("example.com:5678").unwrap();
        assert_eq!(peer_addr(&peer), "example.com:5678");
        assert!(matches!(peer, PeerConfig::Standard(_)));
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
