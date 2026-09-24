use std::{collections::HashMap, path::PathBuf};

use crate::{
    ConfigError,
    tree::path::{ConfigPath, PathSegment},
};

/// Whether to merge by overriding values, or by rejecting any overlapping values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergePolicy {
    /// Reject any overlapping values and return an error if any is found.
    RejectOverlap,
    /// Override any overlapping values with the incoming value.
    Override,
}

/// Where a configuration file/value is coming from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Origin {
    /// The source is the main configuration file.
    MainConfig(PathBuf),
    /// The source is a system configuration file.
    SystemConfig(PathBuf),
    /// The source is a built-in default value.
    BuiltInDefault,
}

/// A unique identifier that represents an origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OriginId(usize);

impl OriginId {
    /// The reserved id for [`Origin::BuiltInDefault`].
    pub const BUILT_IN_DEFAULT: Self = Self(0);
}

/// Tracks the origin ids to specific origins.
#[derive(Debug)]
pub struct ProvenanceTracker {
    origins: HashMap<OriginId, Origin>,
}

impl ProvenanceTracker {
    /// Create an empty provenance tracker.
    pub fn new() -> Self {
        Self {
            origins: HashMap::new(),
        }
    }

    /// Track an origin, returns the origin id for that origin.
    pub fn track(&mut self, origin: Origin) -> OriginId {
        if origin == Origin::BuiltInDefault {
            return OriginId::BUILT_IN_DEFAULT;
        }
        if let Some((id, _)) = self.origins.iter().find(|(_, o)| *o == &origin) {
            return *id;
        }
        // ids start at one, since zero is reserved for the built-in default
        let id = OriginId(self.origins.len() + 1);
        self.origins.insert(id, origin);
        id
    }

    /// Get the origin for a given origin id, if it is known.
    #[cfg(test)]
    pub fn get_origin(&self, id: OriginId) -> Option<&Origin> {
        if id == OriginId::BUILT_IN_DEFAULT {
            return Some(&Origin::BuiltInDefault);
        }
        self.origins.get(&id)
    }
}

impl Default for ProvenanceTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Recursively attributes the explicitly set nodes of a document to the origin
/// registered for it. This follows tree structure, independently of how a node
/// merges: a vector is atomic when merging, but recursive here.
pub trait Attribute {
    fn attribute(&mut self, origin: OriginId);
}

impl<T> Attribute for Vec<T>
where
    T: Attribute,
{
    fn attribute(&mut self, origin: OriginId) {
        for element in self {
            element.attribute(origin);
        }
    }
}

/// The context within the current merge operation.
///
/// This holds operation-scoped state only. Provenance is carried by the
/// settings themselves, so merging needs no access to the origin registry; the
/// [`ConfigMerger`] owns that and resolves ids when reporting diagnostics.
pub struct MergeContext {
    pub policy: MergePolicy,
    pub path: ConfigPath,
}

impl MergeContext {
    pub fn new(policy: MergePolicy) -> Self {
        Self {
            policy,
            path: ConfigPath::root(),
        }
    }

    pub fn at<R>(&mut self, segment: impl Into<PathSegment>, f: impl FnOnce(&mut Self) -> R) -> R {
        self.path.push(segment);
        let result = f(self);
        self.path.pop();
        result
    }
}

/// Allows the merging of two values following the merge policy in the merge
/// context.
pub trait Merge {
    fn merge(&mut self, incoming: Self, context: &mut MergeContext) -> Result<(), ConfigError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_built_in_default_origin_is_reserved() {
        let mut tracker = ProvenanceTracker::new();

        // it resolves without ever having been registered
        assert_eq!(
            tracker.get_origin(OriginId::BUILT_IN_DEFAULT),
            Some(&Origin::BuiltInDefault)
        );
        // and registering it hands back the reserved id rather than a new one
        assert_eq!(
            tracker.track(Origin::BuiltInDefault),
            OriginId::BUILT_IN_DEFAULT
        );

        // no tracked origin may collide with the reserved id
        let first = tracker.track(Origin::MainConfig("/etc/ntp.toml".into()));
        let second = tracker.track(Origin::SystemConfig("/etc/ntp.d/a.toml".into()));
        assert_ne!(first, OriginId::BUILT_IN_DEFAULT);
        assert_ne!(second, OriginId::BUILT_IN_DEFAULT);
        assert_ne!(first, second);
        assert_eq!(
            tracker.get_origin(first),
            Some(&Origin::MainConfig("/etc/ntp.toml".into()))
        );
    }
}
