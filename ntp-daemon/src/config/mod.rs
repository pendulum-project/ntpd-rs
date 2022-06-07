mod peer;

pub use peer::*;

use clap::Parser;
use ntp_proto::SystemConfig;
use serde::{de, Deserialize, Deserializer};
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};
use thiserror::Error;
use tokio::{fs::read_to_string, io};
use tracing::info;
use tracing_subscriber::filter::{self, EnvFilter};

fn default_socket_directory() -> PathBuf {
    PathBuf::from("/run/ntpd-rs")
}

fn parse_env_filter(input: &str) -> Result<EnvFilter, filter::ParseError> {
    EnvFilter::builder().with_regex(false).parse(input)
}

fn deserialize_option_env_filter<'de, D>(deserializer: D) -> Result<Option<EnvFilter>, D::Error>
where
    D: Deserializer<'de>,
{
    let data: Option<&str> = Deserialize::deserialize(deserializer)?;
    if let Some(dirs) = data {
        // allow us to recognise configs with an empty log filter directive
        if dirs.is_empty() {
            Ok(None)
        } else {
            Ok(Some(EnvFilter::try_new(dirs).map_err(de::Error::custom)?))
        }
    } else {
        Ok(None)
    }
}

#[derive(Parser, Debug)]
pub struct CmdArgs {
    #[clap(short, long = "peer", global = true, value_name = "SERVER")]
    pub peers: Vec<PeerConfig>,

    #[clap(short, long, parse(from_os_str), global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[clap(long, short, global = true, parse(try_from_str = parse_env_filter), env = "NTP_LOG")]
    pub log_filter: Option<EnvFilter>,
}

#[derive(Deserialize, Debug, Default)]
pub struct Config {
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub system: SystemConfig,
    #[serde(deserialize_with = "deserialize_option_env_filter", default)]
    pub log_filter: Option<EnvFilter>,
    #[cfg(feature = "sentry")]
    #[serde(default)]
    pub sentry: SentryConfig,
    #[serde(default = "default_socket_directory")]
    pub sockets: PathBuf,
}

#[cfg(feature = "sentry")]
#[derive(Deserialize, Debug, Default)]
pub struct SentryConfig {
    pub dsn: Option<String>,
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f32,
}

#[cfg(feature = "sentry")]
fn default_sample_rate() -> f32 {
    0.0
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("io error while reading config: {0}")]
    Io(#[from] io::Error),
    #[error("config toml parsing error: {0}")]
    Toml(#[from] toml::de::Error),
}

impl Config {
    async fn from_file(file: impl AsRef<Path>) -> Result<Config, ConfigError> {
        let contents = read_to_string(file).await?;
        Ok(toml::de::from_str(&contents)?)
    }

    async fn from_first_file(file: Option<impl AsRef<Path>>) -> Result<Config, ConfigError> {
        // if an explicit file is given, always use that one
        if let Some(f) = file {
            return Config::from_file(f).await;
        }

        // try ntp.toml in working directory or skip if file doesn't exist
        match Config::from_file("./ntp.toml").await {
            Err(ConfigError::Io(e)) if e.kind() == ErrorKind::NotFound => {}
            other => return other,
        }

        // for the global file we also ignore it when there are permission errors
        match Config::from_file("/etc/ntp.toml").await {
            Err(ConfigError::Io(e))
                if e.kind() == ErrorKind::NotFound || e.kind() == ErrorKind::PermissionDenied => {}
            other => return other,
        }

        Ok(Config::default())
    }

    pub async fn from_args(
        file: Option<impl AsRef<Path>>,
        peers: Vec<PeerConfig>,
    ) -> Result<Config, ConfigError> {
        let mut config = Config::from_first_file(file).await?;

        if !peers.is_empty() {
            if !config.peers.is_empty() {
                info!("overriding peers from configuration");
            }
            config.peers = peers;
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config() {
        let config: Config = toml::from_str("[[peers]]\naddr = \"example.com\"").unwrap();
        assert_eq!(
            config.peers,
            vec![PeerConfig {
                addr: "example.com:123".into(),
                mode: PeerHostMode::Server
            }]
        );

        let config: Config =
            toml::from_str("log_filter = \"\"\n[[peers]]\naddr = \"example.com\"").unwrap();
        assert!(config.log_filter.is_none());
        assert_eq!(
            config.peers,
            vec![PeerConfig {
                addr: "example.com:123".into(),
                mode: PeerHostMode::Server
            }]
        );

        let config: Config =
            toml::from_str("log_filter = \"info\"\n[[peers]]\naddr = \"example.com\"").unwrap();
        assert!(config.log_filter.is_some());
        assert_eq!(
            config.peers,
            vec![PeerConfig {
                addr: "example.com:123".into(),
                mode: PeerHostMode::Server
            }]
        );

        let config: Config =
            toml::from_str("[[peers]]\naddr = \"example.com\"\n[system]\npanic_threshold = 0")
                .unwrap();
        assert_eq!(
            config.peers,
            vec![PeerConfig {
                addr: "example.com:123".into(),
                mode: PeerHostMode::Server
            }]
        );
        assert!(config.system.panic_threshold.is_none());

        let config: Config = toml::from_str(
            r#"
            log_filter = "info"
            sockets = "/foo/bar"
            [[peers]]
            addr = "example.com"
            "#,
        )
        .unwrap();
        assert!(config.log_filter.is_some());
        assert_eq!(config.sockets, PathBuf::from("/foo/bar"));
        assert_eq!(
            config.peers,
            vec![PeerConfig {
                addr: "example.com:123".into(),
                mode: PeerHostMode::Server
            }]
        );
    }

    #[cfg(feature = "sentry")]
    #[test]
    fn test_sentry_config() {
        let config: Config = toml::from_str("[[peers]]\naddr = \"example.com\"").unwrap();
        assert!(config.sentry.dsn.is_none());

        let config: Config =
            toml::from_str("[[peers]]\naddr = \"example.com\"\n[sentry]\ndsn = \"abc\"").unwrap();
        assert_eq!(config.sentry.dsn, Some("abc".into()));

        let config: Config = toml::from_str(
            "[[peers]]\naddr = \"example.com\"\n[sentry]\ndsn = \"abc\"\nsample_rate = 0.5",
        )
        .unwrap();
        assert_eq!(config.sentry.dsn, Some("abc".into()));
        assert!((config.sentry.sample_rate - 0.5).abs() < 1e-9);
    }
}
