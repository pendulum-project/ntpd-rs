use std::str::FromStr;

use serde::Deserialize;
use tracing::metadata::LevelFilter;

#[derive(Debug, Copy, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// The "trace" level.
    ///
    /// Designates very low priority, often extremely verbose, information.
    Trace = 0,
    /// The "debug" level.
    ///
    /// Designates lower priority information.
    Debug = 1,
    /// The "info" level.
    ///
    /// Designates useful information.
    Info = 2,
    /// The "warn" level.
    ///
    /// Designates hazardous situations.
    Warn = 3,
    /// The "error" level.
    ///
    /// Designates very serious errors.
    Error = 4,
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Info
    }
}

pub struct UnknownLogLevel;

impl FromStr for LogLevel {
    type Err = UnknownLogLevel;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            _ => Err(UnknownLogLevel),
        }
    }
}

impl Into<tracing::Level> for LogLevel {
    fn into(self) -> tracing::Level {
        match self {
            LogLevel::Trace => tracing::Level::TRACE,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Error => tracing::Level::ERROR,
        }
    }
}

impl Into<LevelFilter> for LogLevel {
    fn into(self) -> LevelFilter {
        LevelFilter::from_level(self.into())
    }
}

pub fn tracing_init(level: impl Into<LevelFilter>) -> tracing_subscriber::fmt::Subscriber {
    tracing_subscriber::fmt().with_max_level(level).finish()
}
