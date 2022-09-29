use std::{
    fmt,
    net::{AddrParseError, SocketAddr},
    str::FromStr,
    time::Duration,
};

use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer,
};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ServerConfig {
    pub addr: SocketAddr,
    pub rate_limiting_cache_size: usize,
    pub rate_limiting_cutoff: Duration,
}

impl TryFrom<&str> for ServerConfig {
    type Error = AddrParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(ServerConfig {
            addr: SocketAddr::from_str(value)?,
            rate_limiting_cache_size: Default::default(),
            rate_limiting_cutoff: Default::default(),
        })
    }
}

// We have a custom deserializer for serverconfig because we
// want to deserialize it from either a string or a map
impl<'de> Deserialize<'de> for ServerConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ServerConfigVisitor;

        impl<'de> Visitor<'de> for ServerConfigVisitor {
            type Value = ServerConfig;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("string or map")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<ServerConfig, E> {
                TryFrom::try_from(value).map_err(de::Error::custom)
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<ServerConfig, M::Error> {
                let mut addr = None;
                let mut rate_limiting_cache_size = None;
                let mut rate_limiting_cutoff = None;
                while let Some(key) = map.next_key::<&str>()? {
                    match key {
                        "addr" => {
                            if addr.is_some() {
                                return Err(de::Error::duplicate_field("addr"));
                            }
                            let raw: &str = map.next_value()?;

                            addr = Some(SocketAddr::from_str(raw).map_err(de::Error::custom)?);
                        }
                        "rate_limiting_cache_size" => {
                            if addr.is_some() {
                                return Err(de::Error::duplicate_field("rate_limiting_cache_size"));
                            }

                            rate_limiting_cache_size = Some(map.next_value()?);
                        }
                        "rate_limiting_cutoff_ms" => {
                            if addr.is_some() {
                                return Err(de::Error::duplicate_field("rate_limiting_cutoff_ms"));
                            }

                            rate_limiting_cutoff = Some(Duration::from_millis(map.next_value()?));
                        }
                        _ => {
                            return Err(de::Error::unknown_field(
                                key,
                                &[
                                    "addr",
                                    "rate_limiting_cache_size",
                                    "rate_limiting_cutoff_ms",
                                ],
                            ));
                        }
                    }
                }

                let addr = addr.ok_or_else(|| de::Error::missing_field("addr"))?;
                let rate_limiting_cache_size = rate_limiting_cache_size.unwrap_or_default();
                let rate_limiting_cutoff = rate_limiting_cutoff.unwrap_or_default();
                Ok(ServerConfig {
                    addr,
                    rate_limiting_cache_size,
                    rate_limiting_cutoff,
                })
            }
        }

        deserializer.deserialize_any(ServerConfigVisitor)
    }
}
