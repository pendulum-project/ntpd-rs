use std::{fs::read_to_string, os::unix::fs::PermissionsExt, path::Path};

use log::warn;
use serde::Deserialize;
use statime::{DelayMechanism, Duration, Interval};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    pub loglevel: String,
    pub sdo_id: u16,
    pub domain: u8,
    pub priority1: u8,
    pub priority2: u8,
    pub hardware_clock: Option<String>,
    #[serde(rename = "port")]
    pub ports: Vec<PortConfig>,
}

#[derive(Deserialize, Debug)]
pub struct PortConfig {
    pub interface: String,
    pub announce_interval: i8,
    pub sync_interval: i8,
    pub announce_receipt_timeout: u8,
    pub master_only: bool,
    pub delay_asymetry: i64,
    pub delay_mechanism: i8,
}

impl From<PortConfig> for statime::PortConfig {
    fn from(pc: PortConfig) -> Self {
        Self {
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

#[derive(Deserialize, Debug)]
pub enum PtpMode {
    Ordinary,
    Boundary,
    Transparant,
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
