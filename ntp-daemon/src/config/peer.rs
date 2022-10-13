use std::{fmt, net::SocketAddr};

use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer,
};

#[derive(Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum PeerHostMode {
    #[serde(alias = "server")]
    Server,
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

#[derive(Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct PoolPeerConfig {
    pub addr: NormalizedAddress,
    pub max_peers: usize,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PeerConfig {
    Standard(StandardPeerConfig),
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
    address: String,
}

impl NormalizedAddress {
    /// Specifically, this adds the `:123` port if no port is specified
    fn from_string(mut address: String) -> std::io::Result<Self> {
        if address.split(':').count() > 2 {
            // IPv6, try to parse it as such
            match address.parse::<SocketAddr>() {
                Ok(_) => Ok(Self { address }),
                Err(e) => {
                    // Could be because of no port, add one and see
                    address = format!("[{address}]:123");
                    if address.parse::<SocketAddr>().is_ok() {
                        Ok(Self { address })
                    } else {
                        Err(std::io::Error::new(std::io::ErrorKind::Other, e))
                    }
                }
            }
        } else if let Some((_, port)) = address.split_once(':') {
            // Not ipv6, and we seem to have a port. We cant reasonably
            // check whether the host is valid, but at least check that
            // the port is.
            match port.parse::<u16>() {
                Ok(_) => Ok(Self { address }),
                Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        } else {
            // Not ipv6 and no port. As we cant reasonably check host
            // so just append a port
            address.push_str(":123");
            Ok(Self { address })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.address
    }

    #[cfg(test)]
    pub(crate) fn new_unchecked(value: &str) -> Self {
        Self {
            address: value.to_string(),
        }
    }

    pub async fn lookup_host(&self) -> std::io::Result<impl Iterator<Item = SocketAddr> + '_> {
        tokio::net::lookup_host(&self.address).await
    }
}

impl TryFrom<&str> for StandardPeerConfig {
    type Error = std::io::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            addr: NormalizedAddress::from_string(value.to_string())?,
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
                let mut addr = None;
                let mut mode = None;
                let mut max_peers = None;
                while let Some(key) = map.next_key::<&str>()? {
                    match key {
                        "addr" => {
                            if addr.is_some() {
                                return Err(de::Error::duplicate_field("addr"));
                            }
                            let raw: String = map.next_value()?;

                            let parsed_addr =
                                NormalizedAddress::from_string(raw.as_str().to_string())
                                    .map_err(de::Error::custom)?;

                            addr = Some(parsed_addr);
                        }
                        "mode" => {
                            if mode.is_some() {
                                return Err(de::Error::duplicate_field("mode"));
                            }
                            mode = Some(map.next_value()?);
                        }
                        "max_peers" => {
                            if max_peers.is_some() {
                                return Err(de::Error::duplicate_field("max_peers"));
                            }
                            max_peers = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(de::Error::unknown_field(
                                key,
                                &["addr", "mode", "max_peers"],
                            ));
                        }
                    }
                }

                let addr = addr.ok_or_else(|| de::Error::missing_field("addr"))?;
                let mode = mode.unwrap_or_default();

                match mode {
                    PeerHostMode::Server => {
                        if max_peers.is_some() {
                            Err(de::Error::unknown_field("max_peers", &["addr", "mode"]))
                        } else {
                            Ok(PeerConfig::Standard(StandardPeerConfig { addr }))
                        }
                    }
                    PeerHostMode::Pool => {
                        let max_peers = max_peers.unwrap_or(1);

                        Ok(PeerConfig::Pool(PoolPeerConfig { addr, max_peers }))
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

    fn peer_addr(config: &PeerConfig) -> &str {
        match config {
            PeerConfig::Standard(c) => c.addr.as_str(),
            PeerConfig::Pool(c) => c.addr.as_str(),
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
            assert_eq!(config.addr.as_str(), "example.com:123");
            assert_eq!(config.max_peers, 1);
        }

        let test: TestConfig = toml::from_str(
            r#"
            [peer]
            addr = "example.com"
            mode = "Pool"
            max_peers = 42
            "#,
        )
        .unwrap();
        assert!(matches!(test.peer, PeerConfig::Pool(_)));
        if let PeerConfig::Pool(config) = test.peer {
            assert_eq!(config.addr.as_str(), "example.com:123");
            assert_eq!(config.max_peers, 42);
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
        let addr = NormalizedAddress::from_string("[::1]:456".into()).unwrap();
        assert_eq!(addr.as_str(), "[::1]:456");
        let addr = NormalizedAddress::from_string("::1".into()).unwrap();
        assert_eq!(addr.as_str(), "[::1]:123");
        assert!(NormalizedAddress::from_string(":some:invalid:1".into()).is_err());
        let addr = NormalizedAddress::from_string("127.0.0.1:456".into()).unwrap();
        assert_eq!(addr.as_str(), "127.0.0.1:456");
        let addr = NormalizedAddress::from_string("127.0.0.1".into()).unwrap();
        assert_eq!(addr.as_str(), "127.0.0.1:123");
        let addr = NormalizedAddress::from_string("1234567890.example.com".into()).unwrap();
        assert_eq!(addr.as_str(), "1234567890.example.com:123");
    }
}
