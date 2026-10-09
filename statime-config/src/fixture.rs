//! A small configuration for the tests to use.
//!
//! The tests describe the machinery, not any particular configuration, so they
//! use this rather than whatever configuration the crate happens to define.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{Configurable, ConfigurableAtomic, RootConfig, load::SystemConfigSetting};

#[derive(Debug, Clone, PartialEq, Eq, Configurable)]
pub struct Fixture {
    #[config(default)]
    pub use_system_config: UseSystemConfig,

    #[config(default)]
    pub sources: Vec<Source>,

    pub logging: Logging,
}

impl RootConfig for Fixture {
    fn use_system_config(partial: &Self::Partial) -> SystemConfigSetting {
        match partial.use_system_config.clone().into_option() {
            Some(UseSystemConfig::Enabled(false)) => SystemConfigSetting::None,
            Some(UseSystemConfig::Enabled(true)) => {
                SystemConfigSetting::DefaultPath(UseSystemConfig::DEFAULT_SYSTEM_CONFIG.into())
            }
            Some(UseSystemConfig::Directory(path)) => SystemConfigSetting::UserSpecifiedPath(path),
            None => SystemConfigSetting::Unset,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Configurable)]
#[config(tag = "kind")]
pub enum Source {
    #[config(rename = "server")]
    Server(Server),
    Pool(Pool),
}

#[derive(Debug, Clone, PartialEq, Eq, Configurable)]
pub struct Server {
    /// Required: no document supplying it is an error.
    pub address: String,

    #[config(default = 4)]
    pub version: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Configurable)]
pub struct Pool {
    pub address: String,

    #[config(default = 4)]
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Configurable)]
pub struct Logging {
    #[config(default = Level::Info)]
    pub level: Level,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ConfigurableAtomic)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

/// Which system configuration to layer underneath the main configuration, if
/// any.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ConfigurableAtomic)]
#[serde(untagged)]
pub enum UseSystemConfig {
    /// `true` reads the fragments supplied by the distribution, `false` uses no
    /// system configuration at all.
    Enabled(bool),

    /// A directory to read the fragments from, instead of the default one.
    Directory(PathBuf),
}

impl UseSystemConfig {
    pub const DEFAULT_SYSTEM_CONFIG: &str = "/usr/lib/ntpd-rs/system-config";
}

impl Default for UseSystemConfig {
    fn default() -> Self {
        Self::Enabled(false)
    }
}
