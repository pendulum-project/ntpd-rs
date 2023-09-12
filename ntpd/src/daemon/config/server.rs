use std::{
    net::{AddrParseError, SocketAddr},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use serde::{Deserialize, Deserializer};

use super::super::ipfilter::IpFilter;

#[derive(Debug, PartialEq, Eq, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct KeysetConfig {
    /// Number of old keys to keep around
    #[serde(default = "default_stale_key_count")]
    pub stale_key_count: usize,
    /// How often to rotate keys (seconds between rotations)
    #[serde(default = "default_key_rotation_interval")]
    pub key_rotation_interval: usize,
    #[serde(default)]
    pub key_storage_path: Option<String>,
}

impl Default for KeysetConfig {
    fn default() -> Self {
        Self {
            stale_key_count: default_stale_key_count(),
            key_rotation_interval: default_key_rotation_interval(),
            key_storage_path: None,
        }
    }
}

fn default_key_rotation_interval() -> usize {
    // 1 day in seconds
    86400
}

fn default_stale_key_count() -> usize {
    // 1 weeks worth at 1 key per day
    7
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterAction {
    Ignore,
    Deny,
}

#[derive(Debug, PartialEq, Eq, Clone, Deserialize)]
pub struct FilterList {
    pub filter: IpFilter,
    pub action: FilterAction,
}

impl FilterList {
    #[cfg(test)]
    pub fn new(subnets: &[super::subnet::IpSubnet], action: FilterAction) -> Self {
        Self {
            filter: IpFilter::new(subnets),
            action,
        }
    }

    pub fn all(action: FilterAction) -> Self {
        Self {
            filter: IpFilter::all(),
            action,
        }
    }

    pub fn none(action: FilterAction) -> Self {
        Self {
            filter: IpFilter::none(),
            action,
        }
    }

    pub fn default_denylist() -> Self {
        Self::none(FilterAction::Ignore)
    }

    pub fn default_allowlist() -> Self {
        Self::all(FilterAction::Ignore)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    #[serde(default = "FilterList::default_denylist")]
    pub denylist: FilterList,
    #[serde(default = "FilterList::default_allowlist")]
    pub allowlist: FilterList,
    #[serde(default)]
    pub rate_limiting_cache_size: usize,
    #[serde(
        default,
        rename = "rate-limiting-cutoff-ms",
        deserialize_with = "deserialize_rate_limiting_cutoff"
    )]
    pub rate_limiting_cutoff: Duration,
}

fn deserialize_rate_limiting_cutoff<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Duration, D::Error> {
    Ok(Duration::from_millis(u64::deserialize(deserializer)?))
}

impl TryFrom<&str> for ServerConfig {
    type Error = AddrParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(ServerConfig {
            listen: SocketAddr::from_str(value)?,
            denylist: FilterList::default_denylist(),
            allowlist: FilterList::default_allowlist(),
            rate_limiting_cache_size: Default::default(),
            rate_limiting_cutoff: Default::default(),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NtsKeConfig {
    pub certificate_chain_path: PathBuf,
    pub private_key_path: PathBuf,
    #[serde(default = "default_nts_ke_timeout")]
    pub key_exchange_timeout_ms: u64,
    pub listen: SocketAddr,
}

fn default_nts_ke_timeout() -> u64 {
    1000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_server() {
        #[derive(Deserialize, Debug)]
        struct TestConfig {
            server: ServerConfig,
        }

        let test: TestConfig = toml::from_str(
            r#"
            [server]
            listen = "0.0.0.0:123"
            "#,
        )
        .unwrap();
        assert_eq!(test.server.listen, "0.0.0.0:123".parse().unwrap());
        // Defaults
        assert_eq!(test.server.allowlist.filter, IpFilter::all());
        assert_eq!(test.server.allowlist.action, FilterAction::Ignore);
        assert_eq!(test.server.denylist.filter, IpFilter::none());
        assert_eq!(test.server.denylist.action, FilterAction::Ignore);

        let test: TestConfig = toml::from_str(
            r#"
            [server]
            listen = "127.0.0.1:123"
            rate-limiting-cutoff-ms = 1000
            rate-limiting-cache-size = 32
            "#,
        )
        .unwrap();
        assert_eq!(test.server.listen, "127.0.0.1:123".parse().unwrap());
        assert_eq!(test.server.rate_limiting_cache_size, 32);
        assert_eq!(
            test.server.rate_limiting_cutoff,
            Duration::from_millis(1000)
        );

        let test: TestConfig = toml::from_str(
            r#"
            [server]
            listen = "127.0.0.1:123"

            [server.denylist]
            filter = ["192.168.33.34/24"]
            action = "deny"
            "#,
        )
        .unwrap();
        assert_eq!(test.server.listen, "127.0.0.1:123".parse().unwrap());
        assert_eq!(test.server.denylist.action, FilterAction::Deny);

        let test = dbg!(toml::from_str::<TestConfig>(
            r#"
            [server]
            listen = "127.0.0.1:123"

            [server.allowlist]
            filter = ["192.168.33.34/24"]
            "#,
        ));
        assert!(test.is_err());

        let test = toml::from_str::<TestConfig>(
            r#"
            [server]
            listen = "127.0.0.1:123"

            [server.denylist]
            action = "deny"
            "#,
        );
        assert!(test.is_err());
    }

    #[test]
    fn test_deserialize_keyset() {
        #[derive(Deserialize, Debug)]
        #[serde(rename_all = "kebab-case", deny_unknown_fields)]
        struct TestConfig {
            keyset: KeysetConfig,
        }

        let test: TestConfig = toml::from_str(
            r#"
            [keyset]
            stale-key-count = 5
            key-rotation-interval = 500
            key-storage-path = "key/storage/path.key"
            "#,
        )
        .unwrap();

        assert_ne!(test.keyset, KeysetConfig::default())
    }

    #[test]
    fn test_deserialize_nts_ke() {
        #[derive(Deserialize, Debug)]
        #[serde(rename_all = "kebab-case", deny_unknown_fields)]
        struct TestConfig {
            nts_ke_server: NtsKeConfig,
        }

        let test: TestConfig = toml::from_str(
            r#"
            [nts-ke-server]
            listen = "0.0.0.0:4460"
            certificate-chain-path = "/foo/bar/baz.pem"
            private-key-path = "spam.der"
            "#,
        )
        .unwrap();

        let pem = PathBuf::from("/foo/bar/baz.pem");
        assert_eq!(test.nts_ke_server.certificate_chain_path, pem);
        assert_eq!(
            test.nts_ke_server.private_key_path,
            PathBuf::from("spam.der")
        );
        assert_eq!(test.nts_ke_server.key_exchange_timeout_ms, 1000,);
        assert_eq!(test.nts_ke_server.listen, "0.0.0.0:4460".parse().unwrap(),);
    }
}
