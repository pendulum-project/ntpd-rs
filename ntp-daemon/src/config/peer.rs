use std::{convert::Infallible, fmt, net::SocketAddr, str::FromStr};

use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer,
};

#[derive(Deserialize, Debug)]
pub enum PeerHostMode {
    Server,
}

impl Default for PeerHostMode {
    fn default() -> Self {
        PeerHostMode::Server
    }
}

#[derive(Debug)]
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
                let mode = mode.ok_or_else(|| de::Error::missing_field("mode"))?;
                Ok(PeerConfig { addr, mode })
            }
        }

        deserializer.deserialize_any(PeerConfigVisitor)
    }
}

/// Adds :123 to peer address if it is missing
fn fix_addr(mut addr: String) -> String {
    if addr.parse::<SocketAddr>().is_ok() {
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
