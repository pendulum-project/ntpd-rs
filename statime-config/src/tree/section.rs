use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::tree::merge::{Merge, MergeContext, MergeError};

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

/// A section is a recursive merge boundary: two documents mentioning the same
/// table is never a conflict by itself, so the policy is only consulted by the
/// settings underneath.
impl<T> Merge for Section<T>
where
    T: Merge,
{
    fn merge(&mut self, incoming: Self, context: &mut MergeContext) -> Result<(), MergeError> {
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
