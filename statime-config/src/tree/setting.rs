use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::tree::merge::{Merge, MergeError, MergePolicy};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Setting<T> {
    #[default]
    Unset,
    Set(T),
}

impl<T> Setting<T> {
    pub fn value(value: T) -> Self {
        Self::Set(value)
    }

    pub fn is_unset(&self) -> bool {
        matches!(self, Self::Unset)
    }

    pub fn into_option(self) -> Option<T> {
        match self {
            Self::Unset => None,
            Self::Set(value) => Some(value),
        }
    }

    pub fn unwrap_or(self, default: T) -> T {
        match self {
            Self::Unset => default,
            Self::Set(value) => value,
        }
    }

    pub fn unwrap_or_else(self, default: impl FnOnce() -> T) -> T {
        match self {
            Self::Unset => default(),
            Self::Set(value) => value,
        }
    }

    pub fn unwrap_or_default(self) -> T
    where
        T: Default,
    {
        match self {
            Self::Unset => T::default(),
            Self::Set(value) => value,
        }
    }
}

impl<'de, T> Deserialize<'de> for Setting<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Setting::Set)
    }
}

impl<T> Serialize for Setting<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Set(value) => value.serialize(serializer),
            // note: settings should be marked to be skipped and should never serialize to none
            Self::Unset => serializer.serialize_none(),
        }
    }
}

/// A setting is a leaf node, so we don't need to bother too much about merging.
impl<T> Merge for Setting<T> {
    fn merge(
        &mut self,
        incoming: Self,
        context: &mut super::merge::MergeContext<'_>,
    ) -> Result<(), super::merge::MergeError> {
        let Setting::Set(incoming) = incoming else {
            return Ok(());
        };

        if self.is_unset() || context.policy == MergePolicy::Override {
            *self = Setting::Set(incoming);
        } else if context.policy == MergePolicy::RejectOverlap {
            return Err(MergeError::OverwriteNotAllowed {
                position: context.path.clone(),
                current_value: todo!(),
                incoming_value: todo!(),
            });
        }

        Ok(())
    }
}
