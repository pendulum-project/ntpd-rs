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

use crate::{config::subnet::IpSubnet, ipfilter::IpFilter};

#[derive(Debug, PartialEq, Eq, Copy, Clone, Deserialize)]
pub enum FilterAction {
    Ignore,
    Deny,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ServerConfig {
    pub addr: SocketAddr,
    pub denylist: IpFilter,
    pub denylist_action: FilterAction,
    pub allowlist: IpFilter,
    pub allowlist_action: FilterAction,
    pub rate_limiting_cache_size: usize,
    pub rate_limiting_cutoff: Duration,
}

impl ServerConfig {
    pub(crate) fn try_from_str(value: &str) -> Result<Self, <Self as TryFrom<&str>>::Error> {
        Self::try_from(value)
    }
}

impl TryFrom<&str> for ServerConfig {
    type Error = AddrParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(ServerConfig {
            addr: SocketAddr::from_str(value)?,
            denylist: IpFilter::none(),
            denylist_action: FilterAction::Ignore,
            allowlist: IpFilter::all(),
            allowlist_action: FilterAction::Ignore,
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
                let mut allowlist = None;
                let mut allowlist_action = None;
                let mut denylist = None;
                let mut denylist_action = None;
                while let Some(key) = map.next_key::<&str>()? {
                    match key {
                        "addr" => {
                            if addr.is_some() {
                                return Err(de::Error::duplicate_field("addr"));
                            }
                            addr = Some(map.next_value::<SocketAddr>()?);
                        }
                        "allowlist" => {
                            if allowlist.is_some() {
                                return Err(de::Error::duplicate_field("allowlist"));
                            }
                            let list: Vec<IpSubnet> = map.next_value()?;
                            allowlist = Some(IpFilter::new(&list));
                        }
                        "allowlist-action" => {
                            if allowlist_action.is_some() {
                                return Err(de::Error::duplicate_field("allowlist-action"));
                            }
                            allowlist_action = Some(map.next_value::<FilterAction>()?);
                        }
                        "denylist" => {
                            if denylist.is_some() {
                                return Err(de::Error::duplicate_field("denylist"));
                            }
                            let list: Vec<IpSubnet> = map.next_value()?;
                            denylist = Some(IpFilter::new(&list));
                        }
                        "denylist-action" => {
                            if denylist_action.is_some() {
                                return Err(de::Error::duplicate_field("denylist-action"));
                            }
                            denylist_action = Some(map.next_value::<FilterAction>()?);
                        }
                        "rate-limiting-cache-size" => {
                            if rate_limiting_cache_size.is_some() {
                                return Err(de::Error::duplicate_field("rate-limiting-cache-size"));
                            }

                            rate_limiting_cache_size = Some(map.next_value()?);
                        }
                        "rate-limiting-cutoff-ms" => {
                            if rate_limiting_cutoff.is_some() {
                                return Err(de::Error::duplicate_field("rate-limiting-cutoff-ms"));
                            }

                            rate_limiting_cutoff = Some(Duration::from_millis(map.next_value()?));
                        }
                        _ => {
                            return Err(de::Error::unknown_field(
                                key,
                                &[
                                    "addr",
                                    "allowlist",
                                    "allowlist-action",
                                    "denylist",
                                    "denylist-action",
                                    "rate-limiting-cache-size",
                                    "rate-limiting-cutoff-ms",
                                ],
                            ));
                        }
                    }
                }

                let addr = addr.ok_or_else(|| de::Error::missing_field("addr"))?;
                let (allowlist, allowlist_action) = match allowlist {
                    Some(allowlist) => (
                        allowlist,
                        allowlist_action
                            .ok_or_else(|| de::Error::missing_field("allowlist-action"))?,
                    ),
                    None => (IpFilter::all(), FilterAction::Ignore),
                };
                let (denylist, denylist_action) = match denylist {
                    Some(denylist) => (
                        denylist,
                        denylist_action
                            .ok_or_else(|| de::Error::missing_field("denylist-action"))?,
                    ),
                    None => (IpFilter::none(), FilterAction::Ignore),
                };

                let rate_limiting_cache_size = rate_limiting_cache_size.unwrap_or_default();
                let rate_limiting_cutoff = rate_limiting_cutoff.unwrap_or_default();

                Ok(ServerConfig {
                    addr,
                    allowlist,
                    allowlist_action,
                    denylist,
                    denylist_action,
                    rate_limiting_cache_size,
                    rate_limiting_cutoff,
                })
            }
        }

        deserializer.deserialize_any(ServerConfigVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_peer() {
        #[derive(Deserialize, Debug)]
        struct TestConfig {
            server: ServerConfig,
        }

        let test: TestConfig = toml::from_str(
            r#"
            [server]
            addr = "0.0.0.0:123"
            "#,
        )
        .unwrap();
        assert_eq!(test.server.addr, "0.0.0.0:123".parse().unwrap());

        let test: TestConfig = toml::from_str(
            r#"
            [server]
            addr = "127.0.0.1:123"
            rate-limiting-cutoff-ms = 1000
            rate-limiting-cache-size = 32
            "#,
        )
        .unwrap();
        assert_eq!(test.server.addr, "127.0.0.1:123".parse().unwrap());
        assert_eq!(test.server.rate_limiting_cache_size, 32);
        assert_eq!(
            test.server.rate_limiting_cutoff,
            Duration::from_millis(1000)
        );
    }
}
