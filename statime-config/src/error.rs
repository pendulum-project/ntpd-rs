use crate::tree::{ConfigPath, OriginId};

/// Everything that can go wrong while loading a configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}
