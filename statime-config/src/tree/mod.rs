mod atomic;
mod config_merger;
mod configurable;
mod empty;
mod merge;
mod partial_value;
mod path;
mod section;
mod setting;

pub use atomic::ConfigurableAtomic;
pub use configurable::Configurable;
pub use empty::{EffectivelyUnset, is_effectively_unset};
pub use merge::{Merge, MergeContext, Origin, OriginId};
pub use partial_value::PartialValue;
pub use path::ConfigPath;
pub use section::Section;
pub use setting::Setting;

pub(crate) use config_merger::ConfigMerger;

#[cfg(test)]
mod renaming {
    use super::*;
    use crate::{ConfigError, Configurable};

    #[derive(Debug, Clone, PartialEq, Eq, Configurable)]
    struct Renamed {
        #[config(rename = "the-key")]
        wire_name: u8,

        #[config(rename = "and-another", default = 7)]
        second: u8,
    }

    #[test]
    fn a_renamed_field_is_read_under_its_new_name() {
        let partial: PartialRenamed = toml::from_str("the-key = 3").unwrap();

        assert_eq!(partial.wire_name.get(), Some(&3));
    }

    #[test]
    fn the_field_name_is_no_longer_accepted() {
        let error = toml::from_str::<PartialRenamed>("wire_name = 3").unwrap_err();

        assert!(error.to_string().contains("unknown field `wire_name`"));
    }

    #[test]
    fn diagnostics_name_the_key_the_document_uses() {
        let mut partial = PartialRenamed::default();
        partial.apply_defaults();

        let error = partial.resolve(&mut ConfigPath::root()).unwrap_err();

        let ConfigError::MissingRequiredValue { position } = error else {
            panic!("expected a missing required value, got {error:?}");
        };
        assert_eq!(position.to_string(), "the-key");
    }

    #[test]
    fn renaming_leaves_defaults_alone() {
        let mut partial = PartialRenamed::default();
        partial.apply_defaults();

        assert_eq!(partial.second.get(), Some(&7));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ConfigError, UseSystemConfig,
        fixture::{
            Fixture, Level, Logging, PartialFixture, PartialLogging, PartialServer, PartialSource,
            Server, Source,
        },
        tree::{
            merge::{MergePolicy, Origin, ProvenanceTracker},
            setting::Setting,
        },
    };

    #[test]
    fn test_serialized_roundtrip() {
        let config = PartialFixture {
            use_system_config: Setting::default(),
            sources: Setting::value(vec![PartialSource::Server(PartialServer {
                address: Setting::default(),
                version: Setting::default(),
            })]),
            ..PartialFixture::default()
        };
        let serialized = toml::to_string(&config).unwrap();
        dbg!(&serialized);
        let deserialized: PartialFixture = toml::from_str(&serialized).unwrap();
        assert_eq!(config, deserialized);
    }

    fn logging(level: Setting<Level>) -> PartialFixture {
        PartialFixture {
            logging: Section::Set(PartialLogging { level }),
            ..PartialFixture::default()
        }
    }

    #[test]
    fn a_set_but_empty_section_is_omitted() {
        let config = logging(Setting::Unset);
        assert!(config.is_effectively_unset());

        let serialized = toml::to_string(&config).unwrap();
        assert_eq!(serialized, "");

        let deserialized: PartialFixture = toml::from_str(&serialized).unwrap();
        assert_eq!(deserialized.logging, Section::Unset);
        assert_ne!(deserialized, config);
    }

    #[test]
    fn an_explicitly_empty_vector_is_never_empty() {
        let config = PartialFixture {
            sources: Setting::value(vec![]),
            ..PartialFixture::default()
        };

        assert!(!config.is_effectively_unset());
        assert_eq!(toml::to_string(&config).unwrap(), "sources = []\n");
    }

    #[test]
    fn attaching_an_origin_descends_into_vector_elements() {
        let mut tracker = ProvenanceTracker::new();
        let origin = tracker.track(Origin::MainConfig("/etc/main.toml".into()));

        let mut config = PartialFixture {
            sources: Setting::value(vec![PartialSource::Server(PartialServer {
                address: Setting::value("example.com".to_owned()),
                version: Setting::default(),
            })]),
            ..logging(Setting::Unset)
        };
        config.attribute(origin);

        let Section::Set(logging) = &config.logging else {
            panic!("section should still be set");
        };
        // the vector is atomic when merging, but attribution reaches into it
        assert_eq!(config.sources.origin(), Some(origin));
        let Some([PartialSource::Server(source)]) = config.sources.get().map(|v| &v[..]) else {
            panic!("source should still be present");
        };
        assert_eq!(source.address.origin(), Some(origin));
        // unset settings are never attributed
        assert_eq!(logging.level.origin(), None);
    }

    #[test]
    fn defaults_reach_an_absent_section() {
        let mut config = PartialFixture::default();
        config.apply_defaults();

        let Section::Set(logging) = &config.logging else {
            panic!("the section should have been materialized");
        };
        assert_eq!(logging.level.get(), Some(&Level::Info));
        assert_eq!(logging.level.origin(), Some(OriginId::BUILT_IN_DEFAULT));
        // an empty vector is a meaningful default, not an absence
        assert_eq!(config.sources.get(), Some(&vec![]));
    }

    #[test]
    fn defaults_reach_inside_vector_elements() {
        let mut tracker = ProvenanceTracker::new();
        let main = tracker.track(Origin::MainConfig("/etc/main.toml".into()));

        let mut config = PartialFixture {
            sources: Setting::value(vec![PartialSource::Server(PartialServer {
                address: Setting::value("example.com".to_owned()),
                version: Setting::Unset,
            })]),
            ..PartialFixture::default()
        };
        config.attribute(main);
        config.apply_defaults();

        let Some([PartialSource::Server(source)]) = config.sources.get().map(|v| &v[..]) else {
            panic!("source should still be present");
        };
        // sources[0].address comes from the main config, sources[0].version from
        // the built-in defaults
        assert_eq!(source.address.origin(), Some(main));
        assert_eq!(source.version.get(), Some(&4));
        assert_eq!(source.version.origin(), Some(OriginId::BUILT_IN_DEFAULT));
    }

    #[test]
    fn defaults_never_replace_a_configured_value() {
        let mut config = logging(Setting::value(Level::Debug));
        config.apply_defaults();

        let Section::Set(logging) = &config.logging else {
            panic!("section should still be set");
        };
        assert_eq!(logging.level.get(), Some(&Level::Debug));
        assert_eq!(logging.level.origin(), None);
    }

    fn one_source(address: Setting<String>) -> PartialFixture {
        PartialFixture {
            sources: Setting::value(vec![PartialSource::Server(PartialServer {
                address,
                version: Setting::default(),
            })]),
            ..PartialFixture::default()
        }
    }

    #[test]
    fn resolving_a_defaulted_tree_yields_the_runtime_config() {
        let mut config = one_source(Setting::value("example.com".to_owned()));
        config.apply_defaults();

        let resolved = config.resolve(&mut ConfigPath::root()).unwrap();

        assert_eq!(
            resolved,
            Fixture {
                // defaulted, so they are present without being configured
                use_system_config: UseSystemConfig::Enabled(false),
                sources: vec![Source::Server(Server {
                    address: "example.com".to_owned(),
                    version: 4,
                })],
                logging: Logging { level: Level::Info },
            }
        );
    }

    #[test]
    fn a_missing_required_value_reports_its_path() {
        let mut config = one_source(Setting::Unset);
        config.apply_defaults();

        let error = config.resolve(&mut ConfigPath::root()).unwrap_err();

        let ConfigError::MissingRequiredValue { position } = error else {
            panic!("expected a missing required value, got {error:?}");
        };
        assert_eq!(position.to_string(), "sources[0].address");
    }

    #[test]
    fn mentioning_the_same_section_is_not_a_conflict() {
        let mut effective = logging(Setting::value(Level::Info));
        let incoming = logging(Setting::Unset);

        let tracker = ProvenanceTracker::new();
        let mut context = MergeContext::new(MergePolicy::RejectOverlap, &tracker);
        effective.merge(incoming, &mut context).unwrap();

        assert_eq!(effective, logging(Setting::value(Level::Info)));
    }

    #[test]
    fn conflicting_setting_in_a_section_reports_its_path() {
        let mut effective = logging(Setting::value(Level::Info));
        let incoming = logging(Setting::value(Level::Debug));

        let tracker = ProvenanceTracker::new();
        let mut context = MergeContext::new(MergePolicy::RejectOverlap, &tracker);
        let error = effective.merge(incoming, &mut context).unwrap_err();

        let ConfigError::OverwriteNotAllowed { position, .. } = error else {
            panic!("expected an overwrite conflict, got {error:?}");
        };
        assert_eq!(position.to_string(), "logging.level");
    }
}
