//! Configuration parsing

use serde::{Deserialize, Serialize};

mod error;
mod load;
mod tree;

pub use error::ConfigError;
pub use tree::{ConfigPath, Origin};

/// The configuration of a statime instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub sources: Vec<SourceConfig>,
    pub observability: ObservabilityConfig,
}

/// A time source to synchronize with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceConfig {
    Server(ServerSourceConfig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSourceConfig {
    pub url: String,
    pub ntp_version: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservabilityConfig {
    pub log_level: LogLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}
