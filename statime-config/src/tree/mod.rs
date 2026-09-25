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
        Config, ConfigError, LogLevel, ObservabilityConfig, PartialConfig,
        PartialObservabilityConfig, PartialServerSourceConfig, PartialSourceConfig,
        ServerSourceConfig, SourceConfig, UseSystemConfig,
        tree::{
            merge::{MergePolicy, Origin, ProvenanceTracker},
            setting::Setting,
        },
    };

    #[test]
    fn test_serialized_roundtrip() {
        let config = PartialConfig {
            use_system_config: Setting::default(),
            sources: Setting::value(vec![PartialSourceConfig::Server(
                PartialServerSourceConfig {
                    url: Setting::default(),
                    ntp_version: Setting::default(),
                },
            )]),
            ..PartialConfig::default()
        };
        let serialized = toml::to_string(&config).unwrap();
        dbg!(&serialized);
        let deserialized: PartialConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(config, deserialized);
    }

    fn observability(log_level: Setting<LogLevel>) -> PartialConfig {
        PartialConfig {
            observability: Section::Set(PartialObservabilityConfig { log_level }),
            ..PartialConfig::default()
        }
    }

    #[test]
    fn a_set_but_empty_section_is_omitted() {
        let config = observability(Setting::Unset);
        assert!(config.is_effectively_unset());

        let serialized = toml::to_string(&config).unwrap();
        assert_eq!(serialized, "");

        let deserialized: PartialConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(deserialized.observability, Section::Unset);
        assert_ne!(deserialized, config);
    }

    #[test]
    fn an_explicitly_empty_vector_is_never_empty() {
        let config = PartialConfig {
            sources: Setting::value(vec![]),
            ..PartialConfig::default()
        };

        assert!(!config.is_effectively_unset());
        assert_eq!(toml::to_string(&config).unwrap(), "sources = []\n");
    }

    #[test]
    fn attaching_an_origin_descends_into_vector_elements() {
        let mut tracker = ProvenanceTracker::new();
        let origin = tracker.track(Origin::MainConfig("/etc/ntp.toml".into()));

        let mut config = PartialConfig {
            sources: Setting::value(vec![PartialSourceConfig::Server(
                PartialServerSourceConfig {
                    url: Setting::value("example.com".to_owned()),
                    ntp_version: Setting::default(),
                },
            )]),
            ..observability(Setting::Unset)
        };
        config.attribute(origin);

        let Section::Set(observability) = &config.observability else {
            panic!("section should still be set");
        };
        // the vector is atomic when merging, but attribution reaches into it
        assert_eq!(config.sources.origin(), Some(origin));
        let Some([PartialSourceConfig::Server(source)]) = config.sources.get().map(|v| &v[..])
        else {
            panic!("source should still be present");
        };
        assert_eq!(source.url.origin(), Some(origin));
        // unset settings are never attributed
        assert_eq!(observability.log_level.origin(), None);
    }

    #[test]
    fn defaults_reach_an_absent_section() {
        let mut config = PartialConfig::default();
        config.apply_defaults();

        let Section::Set(observability) = &config.observability else {
            panic!("the section should have been materialized");
        };
        assert_eq!(observability.log_level.get(), Some(&LogLevel::Info));
        assert_eq!(
            observability.log_level.origin(),
            Some(OriginId::BUILT_IN_DEFAULT)
        );
        // an empty vector is a meaningful default, not an absence
        assert_eq!(config.sources.get(), Some(&vec![]));
    }

    #[test]
    fn defaults_reach_inside_vector_elements() {
        let mut tracker = ProvenanceTracker::new();
        let main = tracker.track(Origin::MainConfig("/etc/ntp.toml".into()));

        let mut config = PartialConfig {
            sources: Setting::value(vec![PartialSourceConfig::Server(
                PartialServerSourceConfig {
                    url: Setting::value("example.com".to_owned()),
                    ntp_version: Setting::Unset,
                },
            )]),
            ..PartialConfig::default()
        };
        config.attribute(main);
        config.apply_defaults();

        let Some([PartialSourceConfig::Server(source)]) = config.sources.get().map(|v| &v[..])
        else {
            panic!("source should still be present");
        };
        // sources[0].url comes from the main config, sources[0].ntp-version
        // from the built-in defaults
        assert_eq!(source.url.origin(), Some(main));
        assert_eq!(source.ntp_version.get(), Some(&4));
        assert_eq!(
            source.ntp_version.origin(),
            Some(OriginId::BUILT_IN_DEFAULT)
        );
    }

    #[test]
    fn defaults_never_replace_a_configured_value() {
        let mut config = observability(Setting::value(LogLevel::Debug));
        config.apply_defaults();

        let Section::Set(observability) = &config.observability else {
            panic!("section should still be set");
        };
        assert_eq!(observability.log_level.get(), Some(&LogLevel::Debug));
        assert_eq!(observability.log_level.origin(), None);
    }

    fn one_server(url: Setting<String>) -> PartialConfig {
        PartialConfig {
            sources: Setting::value(vec![PartialSourceConfig::Server(
                PartialServerSourceConfig {
                    url,
                    ntp_version: Setting::default(),
                },
            )]),
            ..PartialConfig::default()
        }
    }

    #[test]
    fn resolving_a_defaulted_tree_yields_the_runtime_config() {
        let mut config = one_server(Setting::value("example.com".to_owned()));
        config.apply_defaults();

        let resolved = config.resolve(&mut ConfigPath::root()).unwrap();

        assert_eq!(
            resolved,
            Config {
                // defaulted, so they are present without being configured
                use_system_config: UseSystemConfig::Enabled(false),
                sources: vec![SourceConfig::Server(ServerSourceConfig {
                    url: "example.com".to_owned(),
                    ntp_version: 4,
                })],
                observability: ObservabilityConfig {
                    log_level: LogLevel::Info,
                },
            }
        );
    }

    #[test]
    fn a_missing_required_value_reports_its_path() {
        let mut config = one_server(Setting::Unset);
        config.apply_defaults();

        let error = config.resolve(&mut ConfigPath::root()).unwrap_err();

        let ConfigError::MissingRequiredValue { position } = error else {
            panic!("expected a missing required value, got {error:?}");
        };
        assert_eq!(position.to_string(), "sources[0].url");
    }

    #[test]
    fn mentioning_the_same_section_is_not_a_conflict() {
        let mut effective = observability(Setting::value(LogLevel::Info));
        let incoming = observability(Setting::Unset);

        let tracker = ProvenanceTracker::new();
        let mut context = MergeContext::new(MergePolicy::RejectOverlap, &tracker);
        effective.merge(incoming, &mut context).unwrap();

        assert_eq!(effective, observability(Setting::value(LogLevel::Info)));
    }

    #[test]
    fn conflicting_setting_in_a_section_reports_its_path() {
        let mut effective = observability(Setting::value(LogLevel::Info));
        let incoming = observability(Setting::value(LogLevel::Debug));

        let tracker = ProvenanceTracker::new();
        let mut context = MergeContext::new(MergePolicy::RejectOverlap, &tracker);
        let error = effective.merge(incoming, &mut context).unwrap_err();

        let ConfigError::OverwriteNotAllowed { position, .. } = error else {
            panic!("expected an overwrite conflict, got {error:?}");
        };
        assert_eq!(position.to_string(), "observability.log-level");
    }
}
