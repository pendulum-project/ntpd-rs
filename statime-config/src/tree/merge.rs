use std::{collections::HashMap, path::PathBuf};

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

/// Tracks the origin ids to specific origins.
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
        if let Some((id, _)) = self.origins.iter().find(|(_, o)| *o == &origin) {
            return *id;
        }
        let id = OriginId(self.origins.len());
        self.origins.insert(id, origin);
        id
    }

    /// Get the origin for a given origin id, if it is known.
    pub fn get_origin(&self, id: OriginId) -> Option<&Origin> {
        self.origins.get(&id)
    }
}

impl Default for ProvenanceTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// A segment of a path in the tree being merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathSegment {
    Field(&'static str),
    Index(usize),
}

/// Converts a `&'static str` to a [`PathSegment::Field`].
impl From<&'static str> for PathSegment {
    fn from(value: &'static str) -> Self {
        PathSegment::Field(value)
    }
}

/// Converts a `usize` to a [`PathSegment::Index`].
impl From<usize> for PathSegment {
    fn from(value: usize) -> Self {
        PathSegment::Index(value)
    }
}

/// A path in the tree being merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPath(Vec<PathSegment>);

impl ConfigPath {
    pub fn root() -> Self {
        Self(vec![])
    }

    pub fn at<R>(&mut self, segment: impl Into<PathSegment>, f: impl FnOnce(&mut Self) -> R) -> R {
        self.0.push(segment.into());
        let result = f(self);
        self.0.pop();
        result
    }
}

impl std::fmt::Display for ConfigPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (pos, segment) in self.0.iter().enumerate() {
            match segment {
                PathSegment::Field(field) => {
                    if pos != 0 {
                        write!(f, ".")?;
                    }
                    write!(f, "{field}")?
                }
                PathSegment::Index(index) => write!(f, "[{index}]")?,
            }
        }

        Ok(())
    }
}

/// The context within the current merge operation.
pub struct MergeContext<'a> {
    pub policy: MergePolicy,
    pub path: ConfigPath,
    pub provenance: &'a mut ProvenanceTracker,
}

impl<'a> MergeContext<'a> {
    pub fn new(policy: MergePolicy, provenance: &'a mut ProvenanceTracker) -> Self {
        Self {
            policy,
            path: ConfigPath::root(),
            provenance,
        }
    }

    pub fn at<R>(&mut self, segment: impl Into<PathSegment>, f: impl FnOnce(&mut Self) -> R) -> R {
        self.path.0.push(segment.into());
        let result = f(self);
        self.path.0.pop();
        result
    }
}

pub struct ConfigMerger<T> {
    effective: T,
    provenance: ProvenanceTracker,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeError {
    /// Merge operation would overwrite an existing value at the given path.
    ///
    /// The origins are those of the settings involved; they are `None` when a
    /// setting has not been attributed to a document.
    OverwriteNotAllowed {
        position: ConfigPath,
        current_origin: Option<OriginId>,
        incoming_origin: Option<OriginId>,
    },
}

/// Allows the merging of two values following the merge policy in the merge
/// context.
pub trait Merge {
    fn merge(&mut self, incoming: Self, context: &mut MergeContext<'_>) -> Result<(), MergeError>;
}

impl<T> ConfigMerger<T>
where
    T: Merge,
{
    pub fn new() -> Self
    where
        T: Default,
    {
        Self {
            effective: T::default(),
            provenance: ProvenanceTracker::default(),
        }
    }
}
