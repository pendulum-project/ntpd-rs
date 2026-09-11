use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::tree::merge::{Merge, MergeContext, MergeError, MergePolicy, OriginId};

/// An atomic merge boundary in the configuration tree.
///
/// A set setting also records where its value came from if it has been set.
/// Because parsing logic does not understand origins, they are attached
/// separately.
#[derive(Debug, Clone, Default)]
pub enum Setting<T> {
    #[default]
    Unset,
    Set {
        value: T,
        origin: Option<OriginId>,
    },
}

impl<T> Setting<T> {
    /// Create a set setting whose origin is not (yet) known.
    pub fn value(value: T) -> Self {
        Self::Set {
            value,
            origin: None,
        }
    }

    /// Create a set setting originating from `origin`.
    pub fn value_from(value: T, origin: OriginId) -> Self {
        Self::Set {
            value,
            origin: Some(origin),
        }
    }

    /// Return `true` if this setting is unset.
    pub fn is_unset(&self) -> bool {
        matches!(self, Self::Unset)
    }

    /// Return the value in this setting, if it is set.
    pub fn get(&self) -> Option<&T> {
        match self {
            Self::Unset => None,
            Self::Set { value, .. } => Some(value),
        }
    }

    /// The origin of this setting, if it is set and has been attributed.
    pub fn origin(&self) -> Option<OriginId> {
        match self {
            Self::Unset => None,
            Self::Set { origin, .. } => *origin,
        }
    }

    /// Attribute the value in this setting to `origin`.
    pub fn attribute(&mut self, origin: OriginId) {
        if let Self::Set { origin: slot, .. } = self {
            *slot = Some(origin);
        }
    }

    /// Consume this setting, returning the value in it, if it is set.
    pub fn into_option(self) -> Option<T> {
        match self {
            Self::Unset => None,
            Self::Set { value, .. } => Some(value),
        }
    }
}

/// Two settings are equal when they carry equal values.
impl<T> PartialEq for Setting<T>
where
    T: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Unset, Self::Unset) => true,
            (Self::Set { value: this, .. }, Self::Set { value: other, .. }) => this == other,
            _ => false,
        }
    }
}

impl<T> Eq for Setting<T> where T: Eq {}

impl<'de, T> Deserialize<'de> for Setting<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Setting::value)
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
            Self::Set { value, .. } => value.serialize(serializer),
            // note: settings should be marked to be skipped and should never serialize to none
            Self::Unset => serializer.serialize_none(),
        }
    }
}

/// A setting is a leaf node, so we don't need to bother too much about merging.
impl<T> Merge for Setting<T> {
    fn merge(&mut self, incoming: Self, context: &mut MergeContext) -> Result<(), MergeError> {
        let Setting::Set { value, origin } = incoming else {
            return Ok(());
        };

        if let Setting::Set {
            origin: current, ..
        } = self
            && context.policy == MergePolicy::RejectOverlap
        {
            return Err(MergeError::OverwriteNotAllowed {
                position: context.path.clone(),
                current_origin: *current,
                incoming_origin: origin,
            });
        }

        *self = Setting::Set { value, origin };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::merge::{ConfigPath, Origin, ProvenanceTracker};

    fn origins() -> (OriginId, OriginId) {
        let mut tracker = ProvenanceTracker::new();
        let first = tracker.track(Origin::SystemConfig("/etc/ntp.d/a.toml".into()));
        let second = tracker.track(Origin::SystemConfig("/etc/ntp.d/b.toml".into()));
        (first, second)
    }

    #[test]
    fn equality_ignores_origin() {
        let (first, second) = origins();

        assert_eq!(
            Setting::value_from(1, first),
            Setting::value_from(1, second)
        );
        assert_eq!(Setting::value_from(1, first), Setting::value(1));
        assert_ne!(Setting::value_from(1, first), Setting::value_from(2, first));
        assert_ne!(Setting::value_from(1, first), Setting::<i32>::Unset);
    }

    #[test]
    fn only_set_settings_are_attributed() {
        let (first, _) = origins();

        let mut setting = Setting::value(1);
        assert_eq!(setting.origin(), None);
        setting.attribute(first);
        assert_eq!(setting.origin(), Some(first));

        let mut unset = Setting::<i32>::Unset;
        unset.attribute(first);
        assert_eq!(unset.origin(), None);
    }

    #[test]
    fn override_replaces_value_and_origin() {
        let (first, second) = origins();
        let mut context = MergeContext::new(MergePolicy::Override);

        let mut setting = Setting::value_from(1, first);
        setting
            .merge(Setting::value_from(2, second), &mut context)
            .unwrap();

        assert_eq!(setting.get(), Some(&2));
        assert_eq!(setting.origin(), Some(second));
    }

    #[test]
    fn reject_overlap_fills_an_unset_setting() {
        let (first, _) = origins();
        let mut context = MergeContext::new(MergePolicy::RejectOverlap);

        let mut setting = Setting::Unset;
        setting
            .merge(Setting::value_from(1, first), &mut context)
            .unwrap();

        assert_eq!(setting.get(), Some(&1));
        assert_eq!(setting.origin(), Some(first));
    }

    #[test]
    fn reject_overlap_reports_both_origins() {
        let (first, second) = origins();
        let mut context = MergeContext::new(MergePolicy::RejectOverlap);

        let mut setting = Setting::value_from(1, first);
        let error = setting
            .merge(Setting::value_from(2, second), &mut context)
            .unwrap_err();

        assert_eq!(
            error,
            MergeError::OverwriteNotAllowed {
                position: ConfigPath::root(),
                current_origin: Some(first),
                incoming_origin: Some(second),
            }
        );
        // the existing value is left untouched by a rejected merge
        assert_eq!(setting.get(), Some(&1));
    }

    #[test]
    fn merging_an_unset_setting_changes_nothing() {
        let (first, _) = origins();

        for policy in [MergePolicy::Override, MergePolicy::RejectOverlap] {
            let mut context = MergeContext::new(policy);

            let mut setting = Setting::value_from(1, first);
            setting.merge(Setting::Unset, &mut context).unwrap();

            assert_eq!(setting.get(), Some(&1));
            assert_eq!(setting.origin(), Some(first));
        }
    }
}
