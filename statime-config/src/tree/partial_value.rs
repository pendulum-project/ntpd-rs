use crate::{
    ConfigError,
    tree::{merge::OriginId, path::ConfigPath},
};

/// A value in a partial configuration tree.
///
/// These are the passes every node takes part in on the way from parsed
/// documents to a finished configuration, in the order they happen: recording
/// which document a value came from, filling in what no document supplied, and
/// producing the final value.
pub trait PartialValue {
    /// What this becomes once the configuration is complete.
    type Resolved;

    /// Record that everything set here came from `origin`.
    ///
    /// This follows tree structure, independently of how a node merges: a
    /// vector is atomic when merging, but recursive here, so that a value
    /// inside one can still say where it came from.
    fn attribute(&mut self, origin: OriginId);

    /// Fill in the built-in defaults of everything still unset.
    ///
    /// This runs after merging.
    fn apply_defaults(&mut self);

    /// Produce the final value, reporting if any required value is still missing.
    fn resolve(self, path: &mut ConfigPath) -> Result<Self::Resolved, ConfigError>;
}

/// A vector is atomic for merging, but every other pass reaches into it.
impl<T> PartialValue for Vec<T>
where
    T: PartialValue,
{
    type Resolved = Vec<T::Resolved>;

    fn attribute(&mut self, origin: OriginId) {
        for element in self {
            element.attribute(origin);
        }
    }

    fn apply_defaults(&mut self) {
        for element in self {
            element.apply_defaults();
        }
    }

    fn resolve(self, path: &mut ConfigPath) -> Result<Self::Resolved, ConfigError> {
        self.into_iter()
            .enumerate()
            .map(|(index, element)| path.at_index(index, |path| element.resolve(path)))
            .collect()
    }
}
