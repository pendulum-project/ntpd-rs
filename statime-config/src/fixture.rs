//! A small configuration for the tests to use.
//!
//! The tests describe the machinery, not any particular configuration, so they
//! use this rather than whatever configuration the crate happens to define.

use serde::{Deserialize, Serialize};

use crate::{Configurable, ConfigurableAtomic, UseSystemConfig};

#[derive(Debug, Clone, PartialEq, Eq, Configurable)]
#[config(root)]
pub struct Fixture {
    #[config(use_system_config, default)]
    pub use_system_config: UseSystemConfig,

    #[config(default)]
    pub sources: Vec<Source>,

    pub logging: Logging,
}

#[derive(Debug, Clone, PartialEq, Eq, Configurable)]
#[config(tag = "kind")]
pub enum Source {
    Server(Server),
}

#[derive(Debug, Clone, PartialEq, Eq, Configurable)]
pub struct Server {
    /// Required: no document supplying it is an error.
    pub address: String,

    #[config(default = 4)]
    pub version: u8,
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
