mod atomic;
mod defaults;
mod empty;
mod merge;
mod section;
mod setting;

use atomic::atomic_value;
use defaults::ApplyDefaults;
use empty::{EffectivelyUnset, is_effectively_unset};
use merge::{Attribute, Merge, MergeContext, MergeError, OriginId};
use section::Section;
use serde::{Deserialize, Serialize};
use setting::Setting;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct PartialConfig {
    #[serde(skip_serializing_if = "is_effectively_unset")]
    pub use_system_config: Setting<bool>,

    #[serde(skip_serializing_if = "is_effectively_unset")]
    pub sources: Setting<Vec<PartialSourceConfig>>,

    #[serde(skip_serializing_if = "is_effectively_unset")]
    pub observability: Section<PartialObservabilityConfig>,
}

impl EffectivelyUnset for PartialConfig {
    fn is_effectively_unset(&self) -> bool {
        self.use_system_config.is_effectively_unset()
            && self.sources.is_effectively_unset()
            && self.observability.is_effectively_unset()
    }
}

impl Attribute for PartialConfig {
    fn attribute(&mut self, origin: OriginId) {
        self.use_system_config.attribute(origin);
        self.sources.attribute(origin);
        self.observability.attribute(origin);
    }
}

impl ApplyDefaults for PartialConfig {
    fn apply_defaults(&mut self) {
        // use-system-config is a loader directive, so it is not defaulted here
        self.sources.default_to(Vec::new());
        self.sources.apply_defaults();
        self.observability.apply_defaults();
    }
}

impl Merge for PartialConfig {
    fn merge(&mut self, incoming: Self, context: &mut MergeContext) -> Result<(), MergeError> {
        context.at("use-system-config", |context| {
            self.use_system_config
                .merge(incoming.use_system_config, context)
        })?;
        context.at("sources", |context| {
            self.sources.merge(incoming.sources, context)
        })?;
        context.at("observability", |context| {
            self.observability.merge(incoming.observability, context)
        })
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "mode")]
pub enum PartialSourceConfig {
    Server(PartialServerSourceConfig),
    #[default]
    #[serde(untagged)]
    Unset,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct PartialServerSourceConfig {
    #[serde(skip_serializing_if = "is_effectively_unset")]
    pub url: Setting<String>,

    #[serde(skip_serializing_if = "is_effectively_unset")]
    pub ntp_version: Setting<u8>,
}

impl ApplyDefaults for PartialSourceConfig {
    fn apply_defaults(&mut self) {
        match self {
            Self::Server(config) => config.apply_defaults(),
            Self::Unset => {}
        }
    }
}

impl Attribute for PartialSourceConfig {
    fn attribute(&mut self, origin: OriginId) {
        match self {
            Self::Server(config) => config.attribute(origin),
            Self::Unset => {}
        }
    }
}

impl EffectivelyUnset for PartialServerSourceConfig {
    fn is_effectively_unset(&self) -> bool {
        self.url.is_effectively_unset() && self.ntp_version.is_effectively_unset()
    }
}

impl ApplyDefaults for PartialServerSourceConfig {
    fn apply_defaults(&mut self) {
        // url is required, so it has no default
        self.ntp_version.default_to(4);
    }
}

impl Attribute for PartialServerSourceConfig {
    fn attribute(&mut self, origin: OriginId) {
        self.url.attribute(origin);
        self.ntp_version.attribute(origin);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

atomic_value!(LogLevel);

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct PartialObservabilityConfig {
    #[serde(skip_serializing_if = "is_effectively_unset")]
    pub log_level: Setting<LogLevel>,
}

impl EffectivelyUnset for PartialObservabilityConfig {
    fn is_effectively_unset(&self) -> bool {
        self.log_level.is_effectively_unset()
    }
}

impl ApplyDefaults for PartialObservabilityConfig {
    fn apply_defaults(&mut self) {
        self.log_level.default_to(LogLevel::Info);
    }
}

impl Attribute for PartialObservabilityConfig {
    fn attribute(&mut self, origin: OriginId) {
        self.log_level.attribute(origin);
    }
}

impl Merge for PartialObservabilityConfig {
    fn merge(&mut self, incoming: Self, context: &mut MergeContext) -> Result<(), MergeError> {
        context.at("log-level", |context| {
            self.log_level.merge(incoming.log_level, context)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::merge::{MergePolicy, Origin, ProvenanceTracker};

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

    #[test]
    fn mentioning_the_same_section_is_not_a_conflict() {
        let mut effective = observability(Setting::value(LogLevel::Info));
        let incoming = observability(Setting::Unset);

        let mut context = MergeContext::new(MergePolicy::RejectOverlap);
        effective.merge(incoming, &mut context).unwrap();

        assert_eq!(effective, observability(Setting::value(LogLevel::Info)));
    }

    #[test]
    fn conflicting_setting_in_a_section_reports_its_path() {
        let mut effective = observability(Setting::value(LogLevel::Info));
        let incoming = observability(Setting::value(LogLevel::Debug));

        let mut context = MergeContext::new(MergePolicy::RejectOverlap);
        let MergeError::OverwriteNotAllowed { position, .. } =
            effective.merge(incoming, &mut context).unwrap_err();

        assert_eq!(position.to_string(), "observability.log-level");
    }
}
