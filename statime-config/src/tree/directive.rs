use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Where `use-system-config = true` reads its fragments from.
const DEFAULT_SYSTEM_CONFIG: &str = "/usr/lib/ntpd-rs/system-config";

/// The system configuration fragments to layer underneath the main
/// configuration, if any.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum UseSystemConfig {
    /// `true` reads the fragments supplied by the distribution, `false` uses no
    /// system configuration at all.
    Enabled(bool),

    /// A directory to read the fragments from, instead of the default one.
    Directory(PathBuf),
}

impl Default for UseSystemConfig {
    fn default() -> Self {
        Self::Enabled(false)
    }
}

impl UseSystemConfig {
    /// The directory to read fragments from, and whether the configuration
    /// named it: a directory that was asked for and is missing is a mistake,
    /// whereas the default one can be missing.
    pub fn directory(&self) -> Option<(PathBuf, bool)> {
        match self {
            Self::Enabled(false) => None,
            Self::Enabled(true) => Some((PathBuf::from(DEFAULT_SYSTEM_CONFIG), false)),
            Self::Directory(path) => Some((path.clone(), true)),
        }
    }
}
