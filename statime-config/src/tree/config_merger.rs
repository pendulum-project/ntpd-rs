use std::path::PathBuf;

use crate::{
    ConfigError,
    tree::{
        defaults::ApplyDefaults,
        merge::{Attributable, Merge, MergeContext, MergePolicy, Origin, ProvenanceTracker},
        path::ConfigPath,
        resolve::Resolve,
    },
};

/// Combines the configuration layers into one configuration.
#[derive(Debug)]
pub struct ConfigMerger<T> {
    effective: T,
    provenance: ProvenanceTracker,
}

impl<T> ConfigMerger<T>
where
    T: Default + Attributable + Merge + ApplyDefaults + Resolve,
{
    pub fn new() -> Self {
        Self {
            effective: T::default(),
            provenance: ProvenanceTracker::new(),
        }
    }

    /// Add a system configuration fragment, where settings are not allowed to
    /// overlap with other system configuration fragments.
    pub fn add_system(&mut self, path: PathBuf, partial: T) -> Result<(), ConfigError> {
        self.add(
            Origin::SystemConfig(path),
            partial,
            MergePolicy::RejectOverlap,
        )
    }

    /// Add the main configuration, which amends and overrides the system configuration (if any).
    pub fn add_main(&mut self, path: PathBuf, partial: T) -> Result<(), ConfigError> {
        self.add(Origin::MainConfig(path), partial, MergePolicy::Override)
    }

    fn add(
        &mut self,
        origin: Origin,
        mut partial: T,
        policy: MergePolicy,
    ) -> Result<(), ConfigError> {
        partial.attribute(self.provenance.track(origin));
        self.effective
            .merge(partial, &mut MergeContext::new(policy, &self.provenance))
    }

    /// Fill in the built-in defaults of everything no document supplied.
    pub fn apply_defaults(&mut self) {
        self.effective.apply_defaults();
    }

    /// Try to produce the final configuration. Fails if any required values are missing.
    pub fn finish(self) -> Result<(T::Resolved, ProvenanceTracker), ConfigError> {
        let Self {
            effective,
            provenance,
        } = self;

        let resolved = effective.resolve(&mut ConfigPath::root())?;

        Ok((resolved, provenance))
    }
}

impl<T> Default for ConfigMerger<T>
where
    T: Default + Attributable + Merge + ApplyDefaults + Resolve,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LogLevel, tree::PartialConfig};

    fn document(contents: &str) -> PartialConfig {
        toml::from_str(contents).unwrap()
    }

    #[test]
    fn the_main_config_overrides_a_fragment() {
        let mut merger = ConfigMerger::new();
        merger
            .add_system(
                "/etc/ntp.d/a.toml".into(),
                document("observability.log-level = 'warn'"),
            )
            .unwrap();
        merger
            .add_main(
                "/etc/ntp.toml".into(),
                document("observability.log-level = 'debug'"),
            )
            .unwrap();
        merger.apply_defaults();

        let (config, _) = merger.finish().unwrap();

        assert_eq!(config.observability.log_level, LogLevel::Debug);
        // untouched by either document, so it comes from the defaults
        assert_eq!(config.sources, vec![]);
    }

    #[test]
    fn two_fragments_may_not_define_the_same_setting() {
        let mut merger = ConfigMerger::new();
        merger
            .add_system(
                "/etc/ntp.d/a.toml".into(),
                document("observability.log-level = 'warn'"),
            )
            .unwrap();

        let error = merger
            .add_system(
                "/etc/ntp.d/b.toml".into(),
                document("observability.log-level = 'error'"),
            )
            .unwrap_err();

        let ConfigError::OverwriteNotAllowed {
            position,
            current_origin,
            incoming_origin,
        } = error
        else {
            panic!("expected an overwrite conflict, got {error:?}");
        };
        assert_eq!(position.to_string(), "observability.log-level");
        assert_eq!(
            current_origin,
            Some(Origin::SystemConfig("/etc/ntp.d/a.toml".into()))
        );
        assert_eq!(
            incoming_origin,
            Some(Origin::SystemConfig("/etc/ntp.d/b.toml".into()))
        );
    }

    #[test]
    fn a_conflict_names_both_documents() {
        let mut merger = ConfigMerger::<PartialConfig>::new();
        merger
            .add_system(
                "/etc/ntp.d/a.toml".into(),
                document("observability.log-level = 'warn'"),
            )
            .unwrap();

        let error = merger
            .add_system(
                "/etc/ntp.d/b.toml".into(),
                document("observability.log-level = 'error'"),
            )
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "`observability.log-level` is set by both `/etc/ntp.d/a.toml` and `/etc/ntp.d/b.toml`"
        );
    }
}
