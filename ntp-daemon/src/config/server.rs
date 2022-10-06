use std::{
    fmt,
    net::{AddrParseError, SocketAddr},
    str::FromStr,
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
                        _ => {
                            return Err(de::Error::unknown_field(key, &["addr"]));
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
                Ok(ServerConfig {
                    addr,
                    allowlist,
                    allowlist_action,
                    denylist,
                    denylist_action,
                })
            }
        }

        deserializer.deserialize_any(ServerConfigVisitor)
    }
}
