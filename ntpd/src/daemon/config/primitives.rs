use std::net::SocketAddr;

use serde::{Deserialize, Serialize, de};
use statime_base::Duration;
use statime_config::ConfigurableAtomic;

#[derive(Debug, Clone, PartialEq, Eq, ConfigurableAtomic)]
pub(crate) struct NetworkAddress {
    pub(crate) server: String,
    pub(crate) port: Option<u16>,
}

impl Serialize for NetworkAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.port {
            Some(port) if self.server.contains(':') => {
                serializer.serialize_str(&format!("[{}]:{}", self.server, port))
            }
            Some(port) => serializer.serialize_str(&format!("{}:{}", self.server, port)),
            None => serializer.serialize_str(&self.server),
        }
    }
}

impl<'de> Deserialize<'de> for NetworkAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let raw_address = String::deserialize(deserializer)?;

        if raw_address.split(':').count() > 2 {
            // Ipv6, parse it
            match raw_address.parse::<SocketAddr>() {
                Ok(socket_addr) => Ok(NetworkAddress {
                    server: socket_addr.ip().to_string(),
                    port: Some(socket_addr.port()),
                }),
                Err(e) => {
                    // Could be because of no port, add one and see
                    let address_with_port = format!("[{raw_address}]:1");
                    if let Ok(socket_addr) = address_with_port.parse::<SocketAddr>() {
                        Ok(NetworkAddress {
                            server: socket_addr.ip().to_string(),
                            port: None,
                        })
                    } else {
                        Err(serde::de::Error::custom(e))
                    }
                }
            }
        } else if let Some((server_name, port)) = raw_address.split_once(':') {
            Ok(NetworkAddress {
                server: server_name.into(),
                port: Some(port.parse().map_err(serde::de::Error::custom)?),
            })
        } else {
            Ok(NetworkAddress {
                server: raw_address,
                port: None,
            })
        }
    }
}
