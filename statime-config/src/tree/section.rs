use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    ConfigError,
    tree::{
        defaults::ApplyDefaults,
        empty::EffectivelyUnset,
        merge::{Attributable, Merge, MergeContext, OriginId},
        path::ConfigPath,
        resolve::Resolve,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Section<T> {
    #[default]
    Unset,
    Set(T),
}

impl<T> Section<T> {
    pub fn is_unset(&self) -> bool {
        matches!(self, Section::Unset)
    }
}

impl<'de, T> Deserialize<'de> for Section<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::Set)
    }
}

impl<T> Serialize for Section<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Set(value) => value.serialize(serializer),
            // note: sections should be marked to be skipped and should never serialize to none
            Self::Unset => serializer.serialize_none(),
        }
    }
}

/// A section says nothing when it is absent, but also when it is present with
/// every descendant setting unset.
impl<T> EffectivelyUnset for Section<T>
where
    T: EffectivelyUnset,
{
    fn is_effectively_unset(&self) -> bool {
        match self {
            Section::Unset => true,
            Section::Set(value) => value.is_effectively_unset(),
        }
    }
}

/// A section records no origin of its own, and visits its children.
impl<T> Attributable for Section<T>
where
    T: Attributable,
{
    fn attribute(&mut self, origin: OriginId) {
        if let Section::Set(value) = self {
            value.attribute(origin);
        }
    }
}

/// An absent section still has to be visited: a document that never mentions
/// a section should still get the defaults of everything inside it.
impl<T> ApplyDefaults for Section<T>
where
    T: ApplyDefaults + Default,
{
    fn apply_defaults(&mut self) {
        if self.is_unset() {
            *self = Section::Set(T::default());
        }

        if let Section::Set(value) = self {
            value.apply_defaults();
        }
    }
}

/// A section resolves to whatever its contents resolve to.
impl<T> Resolve for Section<T>
where
    T: Resolve + Default,
{
    type Resolved = T::Resolved;

    fn resolve(self, path: &mut ConfigPath) -> Result<Self::Resolved, ConfigError> {
        match self {
            Section::Set(value) => value.resolve(path),
            Section::Unset => T::default().resolve(path),
        }
    }
}

/// A section is a recursive merge boundary: two documents mentioning the same
/// table is never a conflict by itself, so the policy is only consulted by the
/// settings underneath.
impl<T> Merge for Section<T>
where
    T: Merge,
{
    fn merge(&mut self, incoming: Self, context: &mut MergeContext<'_>) -> Result<(), ConfigError> {
        let Section::Set(incoming) = incoming else {
            return Ok(());
        };

        match self {
            Section::Set(existing) => existing.merge(incoming, context),
            Section::Unset => {
                *self = Section::Set(incoming);
                Ok(())
            }
        }
    }
}
