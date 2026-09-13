use crate::{error::ConfigError, tree::path::ConfigPath};

/// Converts a defaulted partial tree into the runtime configuration.
pub trait Resolve {
    type Resolved;

    fn resolve(self, path: &mut ConfigPath) -> Result<Self::Resolved, ConfigError>;
}

impl<T> Resolve for Vec<T>
where
    T: Resolve,
{
    type Resolved = Vec<T::Resolved>;

    fn resolve(self, path: &mut ConfigPath) -> Result<Self::Resolved, ConfigError> {
        self.into_iter()
            .enumerate()
            .map(|(index, element)| path.at(index, |path| element.resolve(path)))
            .collect()
    }
}
