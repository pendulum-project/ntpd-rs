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

fn deserialize_peer_addr<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let data = Deserialize::deserialize(deserializer)?;
    Ok(fix_addr(data))
}

#[derive(Deserialize, Debug)]
pub struct PeerConfig {
    #[serde(deserialize_with = "deserialize_peer_addr")]
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

/// Deserializes a peer configuration from either a string or a map
pub(crate) fn deserialize_peer_config<'de, D>(deserializer: D) -> Result<PeerConfig, D::Error>
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

        fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<PeerConfig, M::Error> {
            Deserialize::deserialize(de::value::MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_any(PeerConfigVisitor)
}

/// Deserializes a vec of peerconfigs from a list of strings/maps
pub(crate) fn deserialize_peer_configs<'de, D>(deserializer: D) -> Result<Vec<PeerConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Wrapper(#[serde(deserialize_with = "deserialize_peer_config")] PeerConfig);

    let v = Vec::deserialize(deserializer)?;
    Ok(v.into_iter().map(|Wrapper(config)| config).collect())
}
