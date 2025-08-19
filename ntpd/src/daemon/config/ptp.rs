use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PtpSourceConfig {
    pub path: std::path::PathBuf,
    pub precision: f64,
    pub period: f64,
}
