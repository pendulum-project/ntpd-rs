use std::{
    fmt,
    net::{AddrParseError, SocketAddr},
    str::FromStr,
};

use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ServerConfig {
    pub addr: SocketAddr,
}

impl TryFrom<&str> for ServerConfig {
    type Error = AddrParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(ServerConfig {
            addr: SocketAddr::from_str(value)?,
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
                while let Some(key) = map.next_key::<&str>()? {
                    match key {
                        "addr" => {
                            if addr.is_some() {
                                return Err(de::Error::duplicate_field("addr"));
                            }
                            let raw: &str = map.next_value()?;

                            let parsed_addr =
                                SocketAddr::from_str(raw).map_err(de::Error::custom)?;

                            addr = Some(parsed_addr);
                        }
                        _ => {
                            return Err(de::Error::unknown_field(key, &["addr"]));
                        }
                    }
                }

                let addr = addr.ok_or_else(|| de::Error::missing_field("addr"))?;
                Ok(ServerConfig { addr })
            }
        }

        deserializer.deserialize_any(ServerConfigVisitor)
    }
}
