//! Configuration parsing and setup for statime

use serde::{Deserialize, Serialize};

mod error;
mod tree;

/// The configuration of a statime instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// A loader directive rather than a runtime setting.
    pub use_system_config: Option<bool>,
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
