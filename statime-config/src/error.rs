use std::path::PathBuf;

use crate::tree::{ConfigPath, OriginId};

/// Everything that can go wrong while loading a configuration.
#[derive(Debug)]
pub enum ConfigError {
    /// Merging would overwrite an existing value at the given path.
    OverwriteNotAllowed {
        position: ConfigPath,
        current_origin: Option<OriginId>,
        incoming_origin: Option<OriginId>,
    },

    /// A value that is required, and that has no built-in default, was not
    /// supplied by any document.
    MissingRequiredValue { position: ConfigPath },

    /// A configuration document could not be read.
    CouldNotRead {
        path: PathBuf,
        cause: std::io::Error,
    },

    /// A configuration document is not valid TOML.
    CouldNotParse {
        path: PathBuf,
        cause: toml::de::Error,
    },
}
