//! Configuration parsing and setup for statime

mod tree;

// #[derive(Deserialize, Serialize, Debug, Default)]
// #[serde(rename_all = "kebab-case", deny_unknown_fields)]
// pub struct Config {
//     #[serde(rename = "source", default)]
//     pub sources: Vec<SourceConfig>,
// }

// #[derive(Deserialize, Serialize, Debug)]
// #[serde(rename_all = "kebab-case", deny_unknown_fields)]
// pub enum SourceConfig {
//     #[serde(rename = "ntp")]
//     Ntp(NtpSourceConfig),
// }

// #[derive(Deserialize, Serialize, Debug)]
// #[serde(rename_all = "kebab-case", deny_unknown_fields)]
// pub struct NtpSourceConfig {
//     pub address: NtpAddress,
//     #[serde(
//         default = "default_ntp_version",
//         deserialize_with = "deserialize_ntp_version"
//     )]
//     pub ntp_version: ProtocolVersion,

//     pub poll_interval: PollIntervalConfig,
// }

// #[derive(Deserialize, Serialize, Debug)]
// #[serde(rename_all = "kebab-case", deny_unknown_fields)]
// pub struct PollIntervalConfig {
//     pub min: PollInterval,
//     pub max: PollInterval,
//     pub initial: PollInterval,
// }

// /// Stores when we will next exchange packages with a remote server.
// //
// // The value is in seconds stored in log2 format:
// //
// // - a value of 4 means 2^4 = 16 seconds
// // - a value of 17 is 2^17 = ~36h
// #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
// #[serde(transparent)]
// pub struct PollInterval(i8);

// impl std::fmt::Debug for PollInterval {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "PollInterval({} s)", 2.0_f64.powf(self.0 as _))
//     }
// }

// #[derive(Debug, Clone, PartialEq, Eq)]
// pub struct NtpAddress(pub NormalizedAddress);
