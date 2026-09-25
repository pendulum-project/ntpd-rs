//! Configuration parsing

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// so that the derive macro can name this crate even from inside it
extern crate self as statime_config;

mod error;
mod load;
mod tree;

pub use error::ConfigError;
pub use load::{RootConfig, load};
pub use statime_config_derive::{Configurable, ConfigurableAtomic};
pub use tree::{ConfigPath, Origin};

/// Everything the derive macro's generated code reaches for. Not a stable
/// interface: refer to these through the macro, not by hand.
#[doc(hidden)]
pub mod __private {
    pub use serde::{self, Deserialize, Serialize};

    pub use crate::{
        ConfigError, RootConfig, UseSystemConfig,
        tree::{
            ApplyDefaults, Attributable, ConfigPath, Configurable, ConfigurableAtomic,
            EffectivelyUnset, Merge, MergeContext, OriginId, Resolve, Section, Setting,
            is_effectively_unset,
        },
    };
}

/// The configuration of a statime instance.
#[derive(Debug, Clone, PartialEq, Eq, Configurable)]
#[config(root)]
pub struct Config {
    /// Only the main configuration may set this: a system configuration
    /// fragment cannot decide which fragments get read.
    #[config(use_system_config, default)]
    pub use_system_config: UseSystemConfig,

    #[config(default)]
    pub sources: Vec<SourceConfig>,

    pub observability: ObservabilityConfig,
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

/// A time source to synchronize with.
#[derive(Debug, Clone, PartialEq, Eq, Configurable)]
#[config(tag = "mode")]
pub enum SourceConfig {
    Server(ServerSourceConfig),
}

#[derive(Debug, Clone, PartialEq, Eq, Configurable)]
pub struct ServerSourceConfig {
    pub url: String,

    #[config(default = 4)]
    pub ntp_version: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Configurable)]
pub struct ObservabilityConfig {
    #[config(default = LogLevel::Info)]
    pub log_level: LogLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ConfigurableAtomic)]
#[serde(rename_all = "kebab-case")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}
