use std::{
    fmt::Display,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use tracing::{info, warn};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    pub nts_pool_ke_server: NtsPoolKeConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Toml(toml::de::Error),
}

impl From<std::io::Error> for ConfigError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(value: toml::de::Error) -> Self {
        Self::Toml(value)
    }
}

impl Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error while reading config: {e}"),
            Self::Toml(e) => write!(f, "config toml parsing error: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    #[allow(clippy::unused_self)]
    // TODO impl config check
    pub fn check(&self) -> bool {
        true
    }

    async fn from_file(file: impl AsRef<Path>) -> Result<Config, ConfigError> {
        const S_IWOTH: u32 = 2;

        let meta = std::fs::metadata(&file)?;
        let perm = meta.permissions();

        if perm.mode() & S_IWOTH != 0 {
            warn!("Unrestricted config file permissions: Others can write.");
        }

        let contents = tokio::fs::read_to_string(file).await?;
        Ok(toml::de::from_str(&contents)?)
    }

    pub async fn from_args(file: impl AsRef<Path>) -> Result<Config, ConfigError> {
        let path = file.as_ref();
        info!(?path, "using config file");

        let config = Config::from_file(path).await?;

        Ok(config)
    }
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub log_level: Option<crate::daemon_tracing::LogLevel>,
}

#[derive(Debug, PartialEq, Eq, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NtsPoolKeConfig {
    pub certificate_authority_path: PathBuf,
    pub certificate_chain_path: PathBuf,
    pub private_key_path: PathBuf,
    #[serde(default = "default_nts_ke_timeout")]
    pub key_exchange_timeout_ms: u64,
    pub listen: SocketAddr,
    pub key_exchange_servers: Vec<KeyExchangeServer>,
}

fn default_nts_ke_timeout() -> u64 {
    1000
}

#[derive(Debug, PartialEq, Eq, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct KeyExchangeServer {
    pub domain: String,
    pub port: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_nts_pool_ke() {
        let test: Config = toml::from_str(
            r#"
            [nts-pool-ke-server]
            listen = "0.0.0.0:4460"
            certificate-authority-path = "/foo/bar/ca.pem"
            certificate-chain-path = "/foo/bar/baz.pem"
            private-key-path = "spam.der"
            key-exchange-servers = [
                { domain = "foo.bar", port = 1234 },
                { domain = "bar.foo", port = 4321 },
            ]
            "#,
        )
        .unwrap();

        let ca = PathBuf::from("/foo/bar/ca.pem");
        assert_eq!(test.nts_pool_ke_server.certificate_authority_path, ca);

        let chain = PathBuf::from("/foo/bar/baz.pem");
        assert_eq!(test.nts_pool_ke_server.certificate_chain_path, chain);

        let private_key = PathBuf::from("spam.der");
        assert_eq!(test.nts_pool_ke_server.private_key_path, private_key);

        assert_eq!(test.nts_pool_ke_server.key_exchange_timeout_ms, 1000,);
        assert_eq!(
            test.nts_pool_ke_server.listen,
            "0.0.0.0:4460".parse().unwrap(),
        );

        assert_eq!(
            test.nts_pool_ke_server.key_exchange_servers,
            vec![
                KeyExchangeServer {
                    domain: String::from("foo.bar"),
                    port: 1234
                },
                KeyExchangeServer {
                    domain: String::from("bar.foo"),
                    port: 4321
                },
            ]
        );
    }
}
