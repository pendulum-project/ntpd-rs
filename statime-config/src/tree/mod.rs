mod merge;
mod section;
mod setting;

use section::Section;
use serde::{Deserialize, Serialize};
use setting::Setting;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct PartialConfig {
    #[serde(skip_serializing_if = "Setting::is_unset")]
    pub use_system_config: Setting<bool>,

    #[serde(skip_serializing_if = "Setting::is_unset")]
    pub sources: Setting<Vec<PartialSourceConfig>>,

    #[serde(skip_serializing_if = "Section::is_unset")]
    pub observability: Section<PartialObservabilityConfig>,
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
    #[serde(default, skip_serializing_if = "Setting::is_unset")]
    pub url: Setting<String>,
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
    #[serde(skip_serializing_if = "Setting::is_unset")]
    pub log_level: Setting<LogLevel>,
}

mod tests {
    use super::*;

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
}
