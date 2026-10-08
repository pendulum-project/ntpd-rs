mod ntp_source;
mod server;

use clock_steering::unix::UnixClock;
use ntp_proto::{NtpVersion, ProtocolVersion, SourceConfig, SynchronizationConfig};
pub use ntp_source::*;
use serde::{Deserialize, Deserializer, Serialize};
pub use server::*;
use statime_algo::LinkConfig;
use statime_config::{
    ConfigError, Configurable, ConfigurableAtomic, RootConfig, SystemConfigSetting,
};
use std::io;
use std::{
    fmt::Display,
    io::ErrorKind,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    str::FromStr,
};
use timestamped_socket::interface::InterfaceName;
use tracing::{info, warn};

use super::{clock::NtpClockWrapper, tracing::LogLevel};

const USAGE_MSG: &str = "\
usage: ntp-daemon [-c PATH] [-l LOG_LEVEL]
       ntp-daemon -h
       ntp-daemon -v";

const DESCRIPTOR: &str = "ntp-daemon - synchronize system time";

const HELP_MSG: &str = "Options:
  -c, --config=PATH             change the config .toml file
  -l, --log-level=LOG_LEVEL     change the log level
  -h, --help                    display this help text
  -v, --version                 display version information";

pub fn long_help_message() -> String {
    format!("{DESCRIPTOR}\n\n{USAGE_MSG}\n\n{HELP_MSG}")
}

#[derive(Debug, Default)]
pub(crate) struct NtpDaemonOptions {
    /// Path of the configuration file
    pub config: Option<PathBuf>,
    /// Level for messages to display in logs
    pub log_level: Option<LogLevel>,
    help: bool,
    version: bool,
    pub action: NtpDaemonAction,
}

pub enum CliArg {
    Flag(String),
    Argument(String, String),
    Rest(Vec<String>),
}

impl CliArg {
    pub fn normalize_arguments<I>(
        takes_argument: &[&str],
        takes_argument_short: &[char],
        iter: I,
    ) -> Result<Vec<Self>, String>
    where
        I: IntoIterator<Item = String>,
    {
        // the first argument is the ntp-daemon command - so we can skip it
        let mut arg_iter = iter.into_iter().skip(1);
        let mut processed = vec![];
        let mut rest = vec![];

        while let Some(arg) = arg_iter.next() {
            match arg.as_str() {
                "--" => {
                    rest.extend(arg_iter);
                    break;
                }
                long_arg if long_arg.starts_with("--") => {
                    // --config=/path/to/config.toml
                    let invalid = Err(format!("invalid option: '{long_arg}'"));

                    if let Some((key, value)) = long_arg.split_once('=') {
                        if takes_argument.contains(&key) {
                            processed.push(CliArg::Argument(key.to_string(), value.to_string()));
                        } else {
                            invalid?;
                        }
                    } else if takes_argument.contains(&long_arg) {
                        if let Some(next) = arg_iter.next() {
                            processed.push(CliArg::Argument(long_arg.to_string(), next));
                        } else {
                            Err(format!("'{}' expects an argument", long_arg))?;
                        }
                    } else {
                        processed.push(CliArg::Flag(arg));
                    }
                }
                short_arg if short_arg.starts_with('-') => {
                    // split combined shorthand options
                    for (n, char) in short_arg.trim_start_matches('-').chars().enumerate() {
                        let flag = format!("-{char}");
                        // convert option argument to separate segment
                        if takes_argument_short.contains(&char) {
                            let rest = short_arg[(n + 2)..].trim().to_string();
                            // assignment syntax is not accepted for shorthand arguments
                            if rest.starts_with('=') {
                                Err("invalid option '='")?;
                            }
                            if !rest.is_empty() {
                                processed.push(CliArg::Argument(flag, rest));
                            } else if let Some(next) = arg_iter.next() {
                                processed.push(CliArg::Argument(flag, next));
                            } else if char == 'h' {
                                // short version of --help has no arguments
                                processed.push(CliArg::Flag(flag));
                            } else {
                                Err(format!("'-{char}' expects an argument"))?;
                            }
                            break;
                        }
                        processed.push(CliArg::Flag(flag));
                    }
                }
                _argument => rest.push(arg),
            }
        }

        if !rest.is_empty() {
            processed.push(CliArg::Rest(rest));
        }

        Ok(processed)
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub enum NtpDaemonAction {
    #[default]
    Help,
    Version,
    Run,
}

impl NtpDaemonOptions {
    const TAKES_ARGUMENT: &'static [&'static str] = &["--config", "--log-level"];
    const TAKES_ARGUMENT_SHORT: &'static [char] = &['c', 'l'];

    /// parse an iterator over command line arguments
    pub fn try_parse_from<I, T>(iter: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str> + Clone,
    {
        let mut options = NtpDaemonOptions::default();
        let arg_iter = CliArg::normalize_arguments(
            Self::TAKES_ARGUMENT,
            Self::TAKES_ARGUMENT_SHORT,
            iter.into_iter().map(|x| x.as_ref().to_string()),
        )?
        .into_iter()
        .peekable();

        for arg in arg_iter {
            match arg {
                CliArg::Flag(flag) => match flag.as_str() {
                    "-h" | "--help" => {
                        options.help = true;
                    }
                    "-v" | "--version" => {
                        options.version = true;
                    }
                    option => {
                        Err(format!("invalid option provided: {option}"))?;
                    }
                },
                CliArg::Argument(option, value) => match option.as_str() {
                    "-c" | "--config" => {
                        options.config = Some(PathBuf::from(value));
                    }
                    "-l" | "--log-level" => match LogLevel::from_str(&value) {
                        Ok(level) => options.log_level = Some(level),
                        Err(_) => return Err("invalid log level".into()),
                    },
                    option => {
                        Err(format!("invalid option provided: {option}"))?;
                    }
                },
                CliArg::Rest(_rest) => { /* do nothing, drop remaining arguments */ }
            }
        }

        options.resolve_action();
        // nothing to validate at the moment

        Ok(options)
    }

    /// from the arguments resolve which action should be performed
    fn resolve_action(&mut self) {
        if self.help {
            self.action = NtpDaemonAction::Help;
        } else if self.version {
            self.action = NtpDaemonAction::Version;
        } else {
            self.action = NtpDaemonAction::Run;
        }
    }
}

fn deserialize_ntp_clock<'de, D>(deserializer: D) -> Result<NtpClockWrapper, D::Error>
where
    D: Deserializer<'de>,
{
    let data: Option<PathBuf> = Deserialize::deserialize(deserializer)?;

    if let Some(path) = data {
        tracing::info!("using custom clock {path:?}");

        #[cfg(not(target_os = "linux"))]
        panic!("Custom clock paths not supported on this platform");

        #[cfg(target_os = "linux")]
        Ok(NtpClockWrapper::from(
            UnixClock::open(path).map_err(|e| serde::de::Error::custom(e.to_string()))?,
        ))
    } else {
        tracing::debug!("using REALTIME clock");
        Ok(NtpClockWrapper::from(UnixClock::CLOCK_REALTIME))
    }
}

fn deserialize_interface<'de, D>(deserializer: D) -> Result<Option<InterfaceName>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt_interface_name: Option<InterfaceName> = Deserialize::deserialize(deserializer)?;

    if let Some(interface_name) = opt_interface_name {
        tracing::debug!("using custom interface {}", interface_name);
    } else {
        tracing::trace!("using default interface");
    }

    Ok(opt_interface_name)
}

/// Timestamping mode. This is a hint!
///
/// Your OS or hardware might not actually support some timestamping modes.
/// Unsupported timestamping modes are ignored.
#[derive(Default, Debug, Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum TimestampMode {
    #[cfg_attr(not(any(target_os = "linux", target_os = "freebsd")), default)]
    Software,
    #[cfg_attr(target_os = "freebsd", default)]
    KernelRecv,
    #[cfg_attr(target_os = "linux", default)]
    KernelAll,
    Hardware,
}

impl TimestampMode {
    #[cfg(target_os = "linux")]
    pub(crate) fn as_interface_mode(self) -> timestamped_socket::socket::InterfaceTimestampMode {
        use timestamped_socket::socket::InterfaceTimestampMode::*;
        match self {
            TimestampMode::Software => None,
            TimestampMode::KernelRecv => SoftwareRecv,
            TimestampMode::KernelAll => SoftwareAll,
            TimestampMode::Hardware => HardwareAll,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub(crate) fn as_general_mode(self) -> timestamped_socket::socket::GeneralTimestampMode {
        use timestamped_socket::socket::GeneralTimestampMode::*;
        match self {
            TimestampMode::Software => None,
            TimestampMode::KernelRecv => SoftwareRecv,
            TimestampMode::KernelAll | TimestampMode::Hardware => SoftwareAll,
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    pub(crate) fn as_general_mode(self) -> timestamped_socket::socket::GeneralTimestampMode {
        use timestamped_socket::socket::GeneralTimestampMode::*;
        None
    }
}

#[cfg(target_os = "linux")]
#[derive(Deserialize, Debug, Copy, Clone)]
pub struct CsptpConfig {
    #[serde(default)]
    pub identity: statime_wire::ClockIdentity,
    #[serde(default = "csptp_config_default_priority")]
    pub priority_1: u8,
    #[serde(default = "csptp_config_default_priority")]
    pub priority_2: u8,
    #[serde(default)]
    pub clock_quality: statime_wire::ClockQuality,
    #[serde(default = "csptp_config_default_true")]
    pub ptp_timescale: bool,
    #[serde(default)]
    pub time_traceable: bool,
    #[serde(default)]
    pub frequency_traceable: bool,
}

#[cfg(target_os = "linux")]
impl Default for CsptpConfig {
    fn default() -> Self {
        Self {
            identity: statime_wire::ClockIdentity::default(),
            priority_1: 128,
            priority_2: 128,
            clock_quality: statime_wire::ClockQuality::default(),
            ptp_timescale: true,
            time_traceable: false,
            frequency_traceable: false,
        }
    }
}

#[cfg(target_os = "linux")]
impl From<CsptpConfig> for statime_csptp::CsptpConfig {
    fn from(value: CsptpConfig) -> Self {
        Self {
            identity: value.identity,
            priority_1: value.priority_1,
            priority_2: value.priority_2,
            clock_quality: value.clock_quality,
            ptp_timescale: value.ptp_timescale,
            time_traceable: value.time_traceable,
            frequency_traceable: value.frequency_traceable,
        }
    }
}

#[cfg(target_os = "linux")]
fn csptp_config_default_priority() -> u8 {
    128
}

#[cfg(target_os = "linux")]
fn csptp_config_default_true() -> bool {
    true
}

#[derive(Deserialize, Debug, Copy, Clone, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ClockConfig {
    #[serde(deserialize_with = "deserialize_ntp_clock", default)]
    pub clock: NtpClockWrapper,
    #[serde(deserialize_with = "deserialize_interface", default)]
    pub interface: Option<InterfaceName>,
    pub timestamp_mode: TimestampMode,
}

#[derive(Deserialize, Debug, Clone, Configurable)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub log_level: Option<LogLevel>,
    #[serde(default)]
    pub log_path: Option<PathBuf>,
    #[serde(default)]
    pub log_path_metrics_exporter: Option<PathBuf>,
    #[serde(default)]
    pub ansi_colors: Option<bool>,
    #[serde(default)]
    pub observation_path: Option<PathBuf>,
    #[serde(default = "default_observation_permissions")]
    pub observation_permissions: u32,
    #[serde(default = "default_metrics_exporter_listen")]
    pub metrics_exporter_listen: SocketAddr,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_level: None,
            log_path: None,
            log_path_metrics_exporter: None,
            ansi_colors: None,
            observation_path: None,
            observation_permissions: default_observation_permissions(),
            metrics_exporter_listen: default_metrics_exporter_listen(),
        }
    }
}

const fn default_observation_permissions() -> u32 {
    0o666
}

fn default_metrics_exporter_listen() -> SocketAddr {
    "127.0.0.1:9975".parse().unwrap()
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DaemonSynchronizationConfig {
    #[serde(flatten)]
    pub synchronization_base: SynchronizationConfig,
}

/// Which system configuration to layer underneath the main configuration, if
/// any.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ConfigurableAtomic)]
#[serde(untagged)]
pub enum UseSystemConfig {
    /// `true` reads the fragments supplied by the distribution, `false` uses no
    /// system configuration at all.
    Enabled(bool),

    /// A directory to read the fragments from, instead of the default one.
    Directory(PathBuf),
}

impl UseSystemConfig {
    pub const DEFAULT_SYSTEM_CONFIG: &str = "/usr/lib/ntpd-rs/system-config";
}

impl Default for UseSystemConfig {
    fn default() -> Self {
        Self::Enabled(false)
    }
}

#[derive(Deserialize, Debug, Default, Configurable)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    #[config(rename = "use-system-config", default)]
    #[allow(clippy::struct_field_names)]
    pub use_system_config: UseSystemConfig,
    #[serde(rename = "source", default)]
    #[config(rename = "source", default)]
    pub sources: Vec<NtpSourceConfig>,
    #[serde(rename = "server", default)]
    #[config(rename = "server", default)]
    pub servers: Vec<NtpServerConfig>,
    #[serde(default)]
    pub observability: ObservabilityConfig,
}

impl RootConfig for Config {
    fn use_system_config(partial: &Self::Partial) -> SystemConfigSetting {
        match &partial.use_system_config {
            statime_config::Setting::Unset => SystemConfigSetting::Unset,
            statime_config::Setting::Set {
                value: UseSystemConfig::Enabled(true),
                ..
            } => SystemConfigSetting::DefaultPath(UseSystemConfig::DEFAULT_SYSTEM_CONFIG.into()),
            statime_config::Setting::Set {
                value: UseSystemConfig::Enabled(false),
                ..
            } => SystemConfigSetting::None,
            statime_config::Setting::Set {
                value: UseSystemConfig::Directory(path),
                ..
            } => SystemConfigSetting::UserSpecifiedPath(path.clone()),
        }
    }
}

impl Config {
    fn from_first_file(file: Option<impl AsRef<Path>>) -> Result<Config, ConfigError> {
        // if an explicit file is given, always use that one
        if let Some(f) = file {
            let path: &Path = f.as_ref();
            info!(?path, "using config file");
            return Config::load(f);
        }

        // for the global file we also ignore it when there are permission errors, or if it does not exist.
        let global_path = Path::new("/etc/ntpd-rs/ntp.toml");
        match Config::load(global_path) {
            Err(ConfigError::CouldNotRead { path, cause })
                if path == global_path
                    && (cause.kind() == ErrorKind::NotFound
                        || cause.kind() == ErrorKind::PermissionDenied) =>
            {
                Ok(Config::default())
            }
            result => result,
        }
    }

    pub fn from_args(
        file: Option<&impl AsRef<Path>>,
        sources: Vec<NtpSourceConfig>,
        servers: Vec<NtpServerConfig>,
    ) -> Result<Config, ConfigError> {
        let mut config = Config::from_first_file(file.as_ref())?;

        if !sources.is_empty() {
            if !config.sources.is_empty() {
                info!("overriding sources from configuration");
            }
            config.sources = sources;
        }

        if !servers.is_empty() {
            if !config.servers.is_empty() {
                info!("overriding servers from configuration");
            }
            config.servers = servers;
        }

        Ok(config)
    }

    /// Count potential number of sources in configuration
    fn count_sources(&self) -> usize {
        let mut count = 0;
        for source in &self.sources {
            match source {
                NtpSourceConfig::Standard(_) => count += 1,
                NtpSourceConfig::Nts(_) => count += 1,
                NtpSourceConfig::Pool(config) => count += config.first.count,
                NtpSourceConfig::NtsPool(config) => count += config.first.count,
                NtpSourceConfig::Sock(_) => count += 1,
                #[cfg(feature = "pps")]
                NtpSourceConfig::Pps(_) => {} // PPS sources don't count
                #[cfg(target_os = "linux")]
                NtpSourceConfig::Csptp(_) => count += 1,
            }
        }
        count
    }

    /// Check that the config is reasonable. This function may panic if the
    /// configuration is egregious, although it doesn't do so currently.
    pub fn check(&self) -> bool {
        let mut ok = true;

        // Note: since we only check once logging is fully configured,
        // using those fields should always work. This is also
        // probably a good policy in general (config should always work
        // but we may panic here to protect the user from themselves)
        if self.sources.is_empty() {
            info!("No sources configured. Daemon will not change system time.");
        }

        // FIXME: Reintroduce check on minimum agreeing sources

        // FIXME: Reintroduce check on NTPv5 being draft once fields are available.

        // FIXME: Reintroduce check on NTS configuration once fields are available.

        ok
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp, reason = "Test code")]
mod tests {
    use ntp_proto::{NtpDuration, ProtocolVersion, StepThreshold};

    use super::*;

    #[test]
    fn cli_no_arguments() {
        let arguments: [String; 0] = [];
        let parsed_empty = NtpDaemonOptions::try_parse_from(arguments).unwrap();

        assert!(parsed_empty.config.is_none());
        assert!(parsed_empty.log_level.is_none());
        assert_eq!(parsed_empty.action, NtpDaemonAction::Run);
    }

    #[test]
    fn cli_external_config() {
        let arguments = &["/usr/bin/ntp-daemon", "--config", "other.toml"];
        let parsed_empty = NtpDaemonOptions::try_parse_from(arguments).unwrap();

        assert_eq!(parsed_empty.config, Some("other.toml".into()));
        assert!(parsed_empty.log_level.is_none());
        assert_eq!(parsed_empty.action, NtpDaemonAction::Run);

        let arguments = &["/usr/bin/ntp-daemon", "-c", "other.toml"];
        let parsed_empty = NtpDaemonOptions::try_parse_from(arguments).unwrap();

        assert_eq!(parsed_empty.config, Some("other.toml".into()));
        assert!(parsed_empty.log_level.is_none());
        assert_eq!(parsed_empty.action, NtpDaemonAction::Run);
    }

    #[test]
    fn cli_log_level() {
        let arguments = &["/usr/bin/ntp-daemon", "--log-level", "debug"];
        let parsed_empty = NtpDaemonOptions::try_parse_from(arguments).unwrap();

        assert!(parsed_empty.config.is_none());
        assert_eq!(parsed_empty.log_level.unwrap(), LogLevel::Debug);

        let arguments = &["/usr/bin/ntp-daemon", "-l", "debug"];
        let parsed_empty = NtpDaemonOptions::try_parse_from(arguments).unwrap();

        assert!(parsed_empty.config.is_none());
        assert_eq!(parsed_empty.log_level.unwrap(), LogLevel::Debug);
    }

    #[test]
    fn toml_sources_invalid() {
        let config: Result<Config, _> = toml::from_str(
            r#"
            [[source]]
            mode = "server"
            address = ":invalid:ipv6:123"
            "#,
        );

        assert!(config.is_err());
    }

    #[test]
    fn toml_allow_no_sources() {
        let config: Result<Config, _> = toml::from_str(
            r#"
            [[server]]
            listen = "[::]:123"
            "#,
        );

        //assert!(config.is_ok());
        assert!(config.unwrap().check());
    }

    #[test]
    fn system_config_accumulated_threshold() {
        let config: Result<SynchronizationConfig, _> = toml::from_str(
            r#"
            accumulated-step-panic-threshold = 0
            "#,
        );

        let config = config.unwrap();
        assert!(config.accumulated_step_panic_threshold.is_none());

        let config: Result<SynchronizationConfig, _> = toml::from_str(
            r#"
            accumulated-step-panic-threshold = 1000
            "#,
        );

        let config = config.unwrap();
        assert_eq!(
            config.accumulated_step_panic_threshold,
            Some(NtpDuration::from_seconds(1000.0))
        );
    }

    #[test]
    fn system_config_startup_panic_threshold() {
        let config: Result<SynchronizationConfig, _> = toml::from_str(
            r#"
            startup-step-panic-threshold = { forward = 10, backward = 20 }
            "#,
        );

        let config = config.unwrap();
        assert_eq!(
            config.startup_step_panic_threshold.forward,
            Some(NtpDuration::from_seconds(10.0))
        );
        assert_eq!(
            config.startup_step_panic_threshold.backward,
            Some(NtpDuration::from_seconds(20.0))
        );
    }

    #[test]
    fn duration_not_nan() {
        #[derive(Debug, Deserialize)]
        struct Helper {
            #[expect(unused)]
            duration: NtpDuration,
        }

        let result: Result<Helper, _> = toml::from_str(
            r#"
            duration = nan
            "#,
        );

        let error = result.unwrap_err();
        assert!(error.to_string().contains("expected a valid number"));
    }

    #[test]
    fn step_threshold_not_nan() {
        #[derive(Debug, Deserialize)]
        struct Helper {
            #[expect(unused)]
            threshold: StepThreshold,
        }

        let result: Result<Helper, _> = toml::from_str(
            r#"
            threshold = nan
            "#,
        );

        let error = result.unwrap_err();
        assert!(error.to_string().contains("expected a positive number"));
    }

    #[test]
    fn deny_unknown_fields() {
        let config: Result<SynchronizationConfig, _> = toml::from_str(
            r#"
            unknown-field = 42
            "#,
        );

        let error = config.unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn clock_config() {
        let config: Result<ClockConfig, _> = toml::from_str(
            r#"
            interface = "enp0s31f6"
            timestamp-mode = "software"
            "#,
        );

        let config = config.unwrap();

        let expected = InterfaceName::from_str("enp0s31f6").unwrap();
        assert_eq!(config.interface, Some(expected));

        assert_eq!(config.timestamp_mode, TimestampMode::Software);
    }

    #[test]
    fn daemon_synchronization_config() {
        let config: Result<DaemonSynchronizationConfig, _> = toml::from_str(
            r#"
            does_not_exist = 5
            "#,
        );

        assert!(config.is_err());

        let config: Result<DaemonSynchronizationConfig, _> = toml::from_str(
            r#"
            minimum-agreeing-sources = 2
            "#,
        );

        let config = config.unwrap();
        assert_eq!(config.synchronization_base.minimum_agreeing_sources, 2);
    }
}
