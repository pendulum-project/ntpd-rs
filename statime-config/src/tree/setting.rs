use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    ConfigError,
    tree::{
        defaults::ApplyDefaults,
        empty::EffectivelyUnset,
        merge::{Attribute, Merge, MergeContext, MergePolicy, OriginId},
        path::ConfigPath,
        resolve::Resolve,
    },
};

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
    #[cfg(test)]
    pub fn origin(&self) -> Option<OriginId> {
        match self {
            Self::Unset => None,
            Self::Set { origin, .. } => *origin,
        }
    }

    /// Set this setting to its built-in default if no document supplied a
    /// value.
    pub fn default_to(&mut self, value: T) {
        if self.is_unset() {
            *self = Self::value_from(value, OriginId::BUILT_IN_DEFAULT);
        }
    }

    /// Consume this setting, returning the value in it, if it is set.
    pub fn into_option(self) -> Option<T> {
        match self {
            Self::Unset => None,
            Self::Set { value, .. } => Some(value),
        }
    }

    /// Consume this setting, returning the value in it. If no value is set,
    /// returns an error naming the setting.
    pub fn require(self, path: &ConfigPath) -> Result<T, ConfigError> {
        self.into_option()
            .ok_or_else(|| ConfigError::MissingRequiredValue {
                position: path.clone(),
            })
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

/// Settings are effectively unset if they are just unset or if they are set to
/// their default value with a default origin.
impl<T> EffectivelyUnset for Setting<T> {
    fn is_effectively_unset(&self) -> bool {
        self.is_unset()
    }
}

/// A setting records its own origin, and visits its nested values.
impl<T> Attribute for Setting<T>
where
    T: Attribute,
{
    fn attribute(&mut self, origin: OriginId) {
        if let Self::Set {
            value,
            origin: slot,
        } = self
        {
            *slot = Some(origin);
            value.attribute(origin);
        }
    }
}

/// A setting holds no default of its own; it only lets the defaults of any
/// nested values be applied.
impl<T> ApplyDefaults for Setting<T>
where
    T: ApplyDefaults,
{
    fn apply_defaults(&mut self) {
        if let Self::Set { value, .. } = self {
            value.apply_defaults();
        }
    }
}

/// A setting resolves to whatever its value is.
impl<T> Resolve for Setting<T>
where
    T: Resolve,
{
    type Resolved = T::Resolved;

    fn resolve(self, path: &mut ConfigPath) -> Result<Self::Resolved, ConfigError> {
        self.require(path)?.resolve(path)
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
    fn merge(&mut self, incoming: Self, context: &mut MergeContext<'_>) -> Result<(), ConfigError> {
        let Setting::Set { value, origin } = incoming else {
            return Ok(());
        };

        if let Setting::Set {
            origin: current, ..
        } = self
            && context.policy == MergePolicy::RejectOverlap
        {
            return Err(ConfigError::OverwriteNotAllowed {
                position: context.path.clone(),
                current_origin: context.origin(*current),
                incoming_origin: context.origin(origin),
            });
        }

        *self = Setting::Set { value, origin };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::merge::{Origin, ProvenanceTracker};

    /// Two tracked documents, along with the registry that can name them.
    fn origins() -> (ProvenanceTracker, OriginId, OriginId) {
        let mut tracker = ProvenanceTracker::new();
        let first = tracker.track(Origin::SystemConfig("/etc/ntp.d/a.toml".into()));
        let second = tracker.track(Origin::SystemConfig("/etc/ntp.d/b.toml".into()));
        (tracker, first, second)
    }

    #[test]
    fn equality_ignores_origin() {
        let (_tracker, first, second) = origins();

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
        let (_tracker, first, _) = origins();

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
        let (tracker, first, second) = origins();
        let mut context = MergeContext::new(MergePolicy::Override, &tracker);

        let mut setting = Setting::value_from(1, first);
        setting
            .merge(Setting::value_from(2, second), &mut context)
            .unwrap();

        assert_eq!(setting.get(), Some(&2));
        assert_eq!(setting.origin(), Some(second));
    }

    #[test]
    fn reject_overlap_fills_an_unset_setting() {
        let (tracker, first, _) = origins();
        let mut context = MergeContext::new(MergePolicy::RejectOverlap, &tracker);

        let mut setting = Setting::Unset;
        setting
            .merge(Setting::value_from(1, first), &mut context)
            .unwrap();

        assert_eq!(setting.get(), Some(&1));
        assert_eq!(setting.origin(), Some(first));
    }

    #[test]
    fn reject_overlap_reports_both_origins() {
        let (tracker, first, second) = origins();
        let mut context = MergeContext::new(MergePolicy::RejectOverlap, &tracker);

        let mut setting = Setting::value_from(1, first);
        let error = setting
            .merge(Setting::value_from(2, second), &mut context)
            .unwrap_err();

        let ConfigError::OverwriteNotAllowed {
            position,
            current_origin,
            incoming_origin,
        } = error
        else {
            panic!("expected an overwrite conflict, got {error:?}");
        };
        assert_eq!(position, ConfigPath::root());
        // the error names the documents, not the ids it was built from
        assert_eq!(
            current_origin,
            Some(Origin::SystemConfig("/etc/ntp.d/a.toml".into()))
        );
        assert_eq!(
            incoming_origin,
            Some(Origin::SystemConfig("/etc/ntp.d/b.toml".into()))
        );
        // the existing value is left untouched by a rejected merge
        assert_eq!(setting.get(), Some(&1));
    }

    #[test]
    fn merging_an_unset_setting_changes_nothing() {
        let (tracker, first, _) = origins();

        for policy in [MergePolicy::Override, MergePolicy::RejectOverlap] {
            let mut context = MergeContext::new(policy, &tracker);

            let mut setting = Setting::value_from(1, first);
            setting.merge(Setting::Unset, &mut context).unwrap();

            assert_eq!(setting.get(), Some(&1));
            assert_eq!(setting.origin(), Some(first));
        }
    }
}
