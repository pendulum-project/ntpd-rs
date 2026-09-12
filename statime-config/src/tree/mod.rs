mod empty;
mod merge;
mod section;
mod setting;

use empty::{EffectivelyUnset, is_effectively_unset};
use merge::{Merge, MergeContext, MergeError};
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
pub struct PartialServerSourceConfig {
    #[serde(default, skip_serializing_if = "is_effectively_unset")]
    pub url: Setting<String>,
}

impl EffectivelyUnset for PartialServerSourceConfig {
    fn is_effectively_unset(&self) -> bool {
        self.url.is_effectively_unset()
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

impl Merge for PartialObservabilityConfig {
    fn merge(&mut self, incoming: Self, context: &mut MergeContext) -> Result<(), MergeError> {
        context.at("log-level", |context| {
            self.log_level.merge(incoming.log_level, context)
        })
    }
}

mod tests {
    use super::*;
    use crate::tree::merge::MergePolicy;

    #[test]
    fn test_serialized_roundtrip() {
        let config = PartialConfig {
            use_system_config: Setting::default(),
            sources: Setting::value(vec![PartialSourceConfig::Server(
                PartialServerSourceConfig {
                    url: Setting::default(),
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
