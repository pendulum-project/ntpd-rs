use std::{fs::read_to_string, os::unix::fs::PermissionsExt, path::Path};

use log::warn;
use serde::{Deserialize, Deserializer};
use statime::{ClockIdentity, DelayMechanism, Duration, Interval};
use timestamped_socket::interface::InterfaceName;

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    pub loglevel: String,
    pub sdo_id: u16,
    pub domain: u8,
    #[serde(default, deserialize_with = "deserialize_clock_identity")]
    pub identity: Option<ClockIdentity>,
    pub priority1: u8,
    pub priority2: u8,
    #[serde(rename = "port")]
    pub ports: Vec<PortConfig>,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PortConfig {
    pub interface: InterfaceName,
    #[serde(default, deserialize_with = "deserialize_acceptable_master_list")]
    pub acceptable_master_list: Option<Vec<ClockIdentity>>,
    #[serde(default)]
    pub hardware_clock: Option<String>,
    #[serde(default)]
    pub network_mode: NetworkMode,
    pub announce_interval: i8,
    pub sync_interval: i8,
    pub announce_receipt_timeout: u8,
    #[serde(default)]
    pub master_only: bool,
    pub delay_asymetry: i64,
    pub delay_mechanism: i8,
}

fn deserialize_acceptable_master_list<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<ClockIdentity>>, D::Error>
where
    D: Deserializer<'de>,
{
    use hex::FromHex;
    use serde::de::Error;

    let raw: Vec<&str> = Deserialize::deserialize(deserializer)?;
    let mut result = Vec::with_capacity(raw.len());

    for identity in raw {
        result.push(ClockIdentity(<[u8; 8]>::from_hex(identity).map_err(
            |e| D::Error::custom(format!("Invalid clock identifier: {}", e)),
        )?));
    }

    Ok(Some(result))
}

fn deserialize_clock_identity<'de, D>(deserializer: D) -> Result<Option<ClockIdentity>, D::Error>
where
    D: Deserializer<'de>,
{
    use hex::FromHex;
    use serde::de::Error;
    let raw: &str = Deserialize::deserialize(deserializer)?;
    Ok(Some(ClockIdentity(<[u8; 8]>::from_hex(raw).map_err(
        |e| D::Error::custom(format!("Invalid clock identifier: {}", e)),
    )?)))
}

impl From<PortConfig> for statime::PortConfig<Option<Vec<ClockIdentity>>> {
    fn from(pc: PortConfig) -> Self {
        Self {
            acceptable_master_list: pc.acceptable_master_list,
            announce_interval: Interval::from_log_2(pc.announce_interval),
            sync_interval: Interval::from_log_2(pc.sync_interval),
            announce_receipt_timeout: pc.announce_receipt_timeout,
            master_only: pc.master_only,
            delay_asymmetry: Duration::from_nanos(pc.delay_asymetry),
            delay_mechanism: DelayMechanism::E2E {
                interval: Interval::from_log_2(pc.delay_mechanism),
            },
        }
    }
}

#[derive(Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    #[default]
    Ipv4,
    Ipv6,
}

impl Config {
    /// Parse config from file
    pub fn from_file(file: &Path) -> Result<Config, ConfigError> {
        let meta = std::fs::metadata(file).unwrap();
        let perm = meta.permissions();

        if perm.mode() as libc::mode_t & libc::S_IWOTH != 0 {
            warn!("Unrestricted config file permissions: Others can write.");
        }

        let contents = read_to_string(file).map_err(ConfigError::Io)?;
        let config: Config = toml::de::from_str(&contents).map_err(ConfigError::Toml)?;
        config.warn_when_unreasonable();
        Ok(config)
    }

    /// Warns about unreasonable config values
    pub fn warn_when_unreasonable(&self) {
        if self.ports.is_empty() {
            warn!("No ports configured.");
        }

        if self.ports.len() > 16 {
            warn!("Too many ports are configured.");
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Toml(toml::de::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => writeln!(f, "io error while reading config: {e}"),
            ConfigError::Toml(e) => writeln!(f, "config toml parsing error: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}
