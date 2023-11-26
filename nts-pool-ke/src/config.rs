use std::{
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use thiserror::Error;
use tracing::{info, warn};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    pub nts_pool_ke_server: NtsPoolKeConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("io error while reading config: {0}")]
    Io(#[from] std::io::Error),
    #[error("config toml parsing error: {0}")]
    Toml(#[from] toml::de::Error),
}

impl Config {
    pub fn check(&self) -> bool {
        true
    }

    async fn from_file(file: impl AsRef<Path>) -> Result<Config, ConfigError> {
        let meta = std::fs::metadata(&file)?;
        let perm = meta.permissions();

        const S_IWOTH: u32 = 2;
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
}

fn default_nts_ke_timeout() -> u64 {
    1000
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
    }
}
