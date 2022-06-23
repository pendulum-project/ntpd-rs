use std::{convert::Infallible, fmt, net::ToSocketAddrs, str::FromStr};

use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer,
};

#[derive(Deserialize, Debug, PartialEq, Eq)]
pub enum PeerHostMode {
    Server,
}

impl Default for PeerHostMode {
    fn default() -> Self {
        PeerHostMode::Server
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PeerConfig {
    pub addr: String,
    pub mode: PeerHostMode,
}

impl PeerConfig {
    pub fn new(host: &str) -> PeerConfig {
        PeerConfig {
            addr: fix_addr(host.to_owned()),
            mode: PeerHostMode::Server,
        }
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
                FromStr::from_str(value).map_err(de::Error::custom)
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<PeerConfig, M::Error> {
                let mut addr = None;
                let mut mode = None;
                while let Some(key) = map.next_key::<&str>()? {
                    match key {
                        "addr" => {
                            if addr.is_some() {
                                return Err(de::Error::duplicate_field("addr"));
                            }
                            addr = Some(fix_addr(map.next_value()?));
                        }
                        "mode" => {
                            if mode.is_some() {
                                return Err(de::Error::duplicate_field("mode"));
                            }
                            mode = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(de::Error::unknown_field(key, &["addr", "mode"]));
                        }
                    }
                }
                let addr = addr.ok_or_else(|| de::Error::missing_field("addr"))?;
                let mode = mode.unwrap_or_default();
                Ok(PeerConfig { addr, mode })
            }
        }

        deserializer.deserialize_any(PeerConfigVisitor)
    }
}

/// Adds :123 to peer address if it is missing
fn fix_addr(mut addr: String) -> String {
    if addr.to_socket_addrs().is_ok() {
        return addr;
    }

    addr.push_str(":123");
    addr
}

impl FromStr for PeerConfig {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: We could do some sanity checks here to fail a bit earlier
        Ok(PeerConfig::new(s))
    }
}

impl TryFrom<&str> for PeerConfig {
    type Error = std::io::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut addr = value.to_string();

        match addr.to_socket_addrs() {
            Ok(_) => Ok(PeerConfig {
                addr,
                mode: PeerHostMode::Server,
            }),
            Err(e) => {
                // try to fix the address by adding the NTP port
                addr.push_str(":123");

                if addr.to_socket_addrs().is_ok() {
                    Ok(PeerConfig {
                        addr,
                        mode: PeerHostMode::Server,
                    })
                } else {
                    Err(e)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_peer() {
        #[derive(Deserialize, Debug)]
        struct TestConfig {
            peer: PeerConfig,
        }

        let test: TestConfig = toml::from_str("peer = \"example.com\"").unwrap();
        assert_eq!(test.peer.addr, "example.com:123");
        assert_eq!(test.peer.mode, PeerHostMode::Server);

        let test: TestConfig = toml::from_str("peer = \"example.com:5678\"").unwrap();
        assert_eq!(test.peer.addr, "example.com:5678");
        assert_eq!(test.peer.mode, PeerHostMode::Server);

        let test: TestConfig = toml::from_str("[peer]\naddr = \"example.com\"").unwrap();
        assert_eq!(test.peer.addr, "example.com:123");
        assert_eq!(test.peer.mode, PeerHostMode::Server);

        let test: TestConfig = toml::from_str("[peer]\naddr = \"example.com:5678\"").unwrap();
        assert_eq!(test.peer.addr, "example.com:5678");
        assert_eq!(test.peer.mode, PeerHostMode::Server);

        let test: TestConfig =
            toml::from_str("[peer]\naddr = \"example.com\"\nmode = \"Server\"").unwrap();
        assert_eq!(test.peer.addr, "example.com:123");
        assert_eq!(test.peer.mode, PeerHostMode::Server);
    }

    #[test]
    fn test_peer_from_string() {
        let peer: PeerConfig = "example.com".parse().unwrap();
        assert_eq!(peer.addr, "example.com:123");
        assert_eq!(peer.mode, PeerHostMode::Server);

        let peer: PeerConfig = "example.com:5678".parse().unwrap();
        assert_eq!(peer.addr, "example.com:5678");
        assert_eq!(peer.mode, PeerHostMode::Server);
    }
}
