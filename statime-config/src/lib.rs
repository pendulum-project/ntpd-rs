//! Configuration parsing and setup for statime

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    error::ConfigError,
    tree::{ConfigMerger, PartialConfig},
};

pub mod error;
mod tree;

pub use tree::{ConfigPath, Origin, OriginId, ProvenanceTracker};

/// Load the configuration from `main`, layered on top of the given system
/// configuration fragments, which are read in the order they are given.
pub fn load(
    main: &Path,
    system_fragments: &[PathBuf],
) -> Result<(Config, ProvenanceTracker), ConfigError> {
    let mut merger = ConfigMerger::new();

    for fragment in system_fragments {
        merger.add_system(fragment.clone(), parse(fragment)?)?;
    }
    merger.add_main(main.to_path_buf(), parse(main)?)?;
    merger.apply_defaults();

    merger.finish()
}

fn parse(path: &Path) -> Result<PartialConfig, ConfigError> {
    let contents = std::fs::read_to_string(path).map_err(|cause| ConfigError::CouldNotRead {
        path: path.to_path_buf(),
        cause,
    })?;

    toml::from_str(&contents).map_err(|cause| ConfigError::CouldNotParse {
        path: path.to_path_buf(),
        cause,
    })
}

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
