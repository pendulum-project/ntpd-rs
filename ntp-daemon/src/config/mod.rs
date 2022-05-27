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
    #[serde(deserialize_with = "deserialize_peer_configs")]
    pub peers: Vec<PeerConfig>,
    pub system: SystemConfig,
    #[serde(deserialize_with = "deserialize_option_env_filter")]
    pub log_filter: Option<EnvFilter>,
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
