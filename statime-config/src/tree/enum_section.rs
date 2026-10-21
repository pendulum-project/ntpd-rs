use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    ConfigError, ConfigPath, Merge, MergeContext, OriginId, PartialValue, tree::EffectivelyUnset,
};

/// EnumSections are merge-able partial values within a configuration tree that have no
/// default partial value. This is the case for enums, which may not have a default variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnumSection<T> {
    Unset,
    Set(T),
}

// Ensure default is always implemented for EnumSection<T>, even if T does not implement default.
#[allow(clippy::derivable_impls, reason = "Want this even when T not Default")]
impl<T> Default for EnumSection<T> {
    fn default() -> Self {
        Self::Unset
    }
}

impl<T> EnumSection<T> {
    pub fn is_unset(&self) -> bool {
        matches!(self, EnumSection::Unset)
    }
}

impl<'de, T> Deserialize<'de> for EnumSection<T>
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

impl<T> Serialize for EnumSection<T>
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

/// An EnumSection says nothing when it is absent, but the lack of default partialvalue
/// means that the presence of any partialvalue also indicates it is set.
impl<T> EffectivelyUnset for EnumSection<T> {
    fn is_effectively_unset(&self) -> bool {
        matches!(self, EnumSection::Unset)
    }
}

impl<T> PartialValue for EnumSection<T>
where
    T: PartialValue,
{
    type Resolved = T::Resolved;

    /// A section records no origin of its own, and visits its children.
    fn attribute(&mut self, origin: OriginId) {
        if let EnumSection::Set(value) = self {
            value.attribute(origin);
        }
    }

    /// An absent section still has to be visited: a document that never
    /// mentions a section should still get the defaults of everything inside
    /// it.
    fn apply_defaults(&mut self) {
        if let EnumSection::Set(value) = self {
            value.apply_defaults();
        }
    }

    /// A section resolves to whatever its contents resolve to. An unset one
    /// only reaches this point when resolving without defaulting first, and
    /// resolving the empty struct still reports any required value it misses.
    fn resolve(self, path: &mut ConfigPath) -> Result<Self::Resolved, ConfigError> {
        match self {
            EnumSection::Set(value) => value.resolve(path),
            EnumSection::Unset => Err(ConfigError::MissingRequiredValue {
                position: path.clone(),
            }),
        }
    }
}

/// A section is a recursive merge boundary: two documents mentioning the same
/// table is never a conflict by itself, so the policy is only consulted by the
/// settings underneath.
impl<T> Merge for EnumSection<T>
where
    T: Merge,
{
    fn merge(&mut self, incoming: Self, context: &mut MergeContext<'_>) -> Result<(), ConfigError> {
        let EnumSection::Set(incoming) = incoming else {
            return Ok(());
        };

        match self {
            EnumSection::Set(existing) => existing.merge(incoming, context),
            EnumSection::Unset => {
                *self = EnumSection::Set(incoming);
                Ok(())
            }
        }
    }
}
