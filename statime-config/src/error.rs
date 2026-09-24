use std::{fmt, path::PathBuf};

use crate::tree::{ConfigPath, Origin};

/// Everything that can go wrong while loading a configuration.
#[derive(Debug)]
pub enum ConfigError {
    /// Merging would overwrite an existing value at the given path.
    ///
    /// The origins are those of the settings involved; they are `None` when a
    /// setting has not been attributed to a document.
    OverwriteNotAllowed {
        position: ConfigPath,
        current_origin: Option<Origin>,
        incoming_origin: Option<Origin>,
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

    /// A system configuration fragment set `use-system-config`. Only the main
    /// configuration may do so.
    DirectiveNotAllowed { path: PathBuf },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OverwriteNotAllowed {
                position,
                current_origin,
                incoming_origin,
            } => write!(
                f,
                "`{position}` is set by both {} and {}",
                Described(current_origin),
                Described(incoming_origin),
            ),
            Self::MissingRequiredValue { position } => {
                write!(f, "`{position}` is required, but was never set")
            }
            Self::CouldNotRead { path, cause } => {
                write!(f, "could not read `{}`: {cause}", path.display())
            }
            Self::CouldNotParse { path, cause } => {
                write!(f, "could not parse `{}`: {cause}", path.display())
            }
            Self::DirectiveNotAllowed { path } => write!(
                f,
                "`{}` sets `use-system-config`, which only the main configuration may do",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CouldNotRead { cause, .. } => Some(cause),
            Self::CouldNotParse { cause, .. } => Some(cause),
            _ => None,
        }
    }
}

/// Names the document a value came from, for a setting that may never have been
/// attributed to one.
struct Described<'a>(&'a Option<Origin>);

impl fmt::Display for Described<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(Origin::MainConfig(path)) | Some(Origin::SystemConfig(path)) => {
                write!(f, "`{}`", path.display())
            }
            Some(Origin::BuiltInDefault) => write!(f, "the built-in defaults"),
            None => write!(f, "an unknown document"),
        }
    }
}
