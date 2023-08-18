mod peer;
mod server;
pub mod subnet;

use ntp_os_clock::DefaultNtpClock;
use ntp_proto::{
    DefaultTimeSyncController, PeerDefaultsConfig, SynchronizationConfig, TimeSyncController,
};
use ntp_udp::{EnableTimestamps, InterfaceName};
pub use peer::*;
use serde::{Deserialize, Deserializer};
pub use server::*;
use std::{
    io::ErrorKind,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    str::FromStr,
};
use thiserror::Error;
use tokio::{fs::read_to_string, io};
use tracing::{info, warn};

use super::{spawn::PeerId, tracing::LogLevel};

const USAGE_MSG: &str = "\
usage: ntp-daemon [-c PATH] [-l LOG_LEVEL]
       ntp-daemon -h";

const DESCRIPTOR: &str = "ntp-daemon - synchronize system time";

const HELP_MSG: &str = "Options:
  -c, --config=PATH             change the config .toml file
  -l, --log-filter=LOG_FILTER   change the log filter";

pub fn long_help_message() -> String {
    format!("{DESCRIPTOR}\n\n{USAGE_MSG}\n\n{HELP_MSG}")
}

#[derive(Debug, Default)]
pub(crate) struct NtpDaemonOptions {
    /// Path of the configuration file
    pub config: Option<PathBuf>,
    /// Filter to apply to log messages
    pub log_filter: Option<LogLevel>,
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
        // the first argument is the sudo command - so we can skip it
        let mut arg_iter = iter.into_iter().skip(1);
        let mut processed = vec![];

        while let Some(arg) = arg_iter.next() {
            match arg.as_str() {
                "--" => {
                    processed.push(CliArg::Rest(arg_iter.collect()));
                    break;
                }
                long_arg if long_arg.starts_with("--") => {
                    // --config=/path/to/config.toml
                    let invalid = Err(format!("invalid option: '{long_arg}'"));

                    if let Some((key, value)) = long_arg.split_once('=') {
                        if takes_argument.contains(&key) {
                            processed.push(CliArg::Argument(key.to_string(), value.to_string()))
                        } else {
                            invalid?
                        }
                    } else if takes_argument.contains(&long_arg) {
                        if let Some(next) = arg_iter.next() {
                            processed.push(CliArg::Argument(long_arg.to_string(), next))
                        } else {
                            Err(format!("'{}' expects an argument", &long_arg))?;
                        }
                    } else {
                        processed.push(CliArg::Flag(arg));
                    }
                }
                short_arg if short_arg.starts_with('-') => {
                    // split combined shorthand options
                    for (n, char) in short_arg.trim_start_matches('-').chars().enumerate() {
                        let flag = format!("-{char}");
                        // convert option argument to seperate segment
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
                                Err(format!("'-{}' expects an argument", char))?;
                            }
                            break;
                        } else {
                            processed.push(CliArg::Flag(flag));
                        }
                    }
                }
                _argument => {
                    let mut rest = vec![arg];
                    rest.extend(arg_iter);
                    processed.push(CliArg::Rest(rest));
                    break;
                }
            }
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
    const TAKES_ARGUMENT: &[&'static str] = &["--config", "--log-filter"];
    const TAKES_ARGUMENT_SHORT: &[char] = &['c', 'l'];

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
                    "-l" | "--log-filter" => match LogLevel::from_str(&value) {
                        Ok(filter) => options.log_filter = Some(filter),
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

fn deserialize_ntp_clock<'de, D>(deserializer: D) -> Result<DefaultNtpClock, D::Error>
where
    D: Deserializer<'de>,
{
    let data: Option<PathBuf> = Deserialize::deserialize(deserializer)?;

    if let Some(path) = data {
        tracing::info!("using custom clock {path:?}");
        DefaultNtpClock::from_path(&path).map_err(|e| serde::de::Error::custom(e.to_string()))
    } else {
        tracing::debug!("using REALTIME clock");
        Ok(DefaultNtpClock::realtime())
    }
}

fn deserialize_interface<'de, D>(deserializer: D) -> Result<Option<InterfaceName>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt_interface_name: Option<InterfaceName> = Deserialize::deserialize(deserializer)?;

    if let Some(interface_name) = opt_interface_name {
        tracing::info!("using custom interface {}", interface_name);
    } else {
        tracing::info!("using default interface");
    }

    Ok(opt_interface_name)
}

#[derive(Deserialize, Debug, Copy, Clone, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ClockConfig {
    #[serde(deserialize_with = "deserialize_ntp_clock", default)]
    pub clock: DefaultNtpClock,
    #[serde(deserialize_with = "deserialize_interface", default)]
    pub interface: Option<InterfaceName>,
    pub enable_timestamps: EnableTimestamps,
}

#[derive(Deserialize, Debug, Default, Clone, Copy)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CombinedSynchronizationConfig {
    #[serde(flatten)]
    pub synchronization: SynchronizationConfig,
    #[serde(flatten)]
    pub algorithm: <DefaultTimeSyncController<DefaultNtpClock, PeerId> as TimeSyncController<
        DefaultNtpClock,
        PeerId,
    >>::AlgorithmConfig,
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct LoggingObservabilityConfig {
    #[serde(default)]
    pub log_level: Option<LogLevel>,
    #[serde(flatten, default)]
    pub observe: ObserveConfig,
    #[serde(flatten, default)]
    pub configure: ConfigureConfig,
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    #[serde(alias = "peer")]
    pub peers: Vec<PeerConfig>,
    #[serde(alias = "server", default)]
    pub servers: Vec<ServerConfig>,
    #[serde(alias = "nts-ke-server", default)]
    pub nts_ke: Vec<NtsKeConfig>,
    #[serde(default)]
    pub synchronization: CombinedSynchronizationConfig,
    #[serde(default)]
    pub peer_defaults: PeerDefaultsConfig,
    #[serde(default)]
    pub observability: LoggingObservabilityConfig,
    #[serde(default)]
    pub keyset: KeysetConfig,
    #[serde(default)]
    #[cfg(feature = "hardware-timestamping")]
    pub clock: ClockConfig,
}

impl Config {
    async fn from_file(file: impl AsRef<Path>) -> Result<Config, ConfigError> {
        let meta = std::fs::metadata(&file).unwrap();
        let perm = meta.permissions();

        if perm.mode() as libc::mode_t & libc::S_IWOTH != 0 {
            warn!("Unrestricted config file permissions: Others can write.");
        }

        let contents = read_to_string(file).await?;
        Ok(toml::de::from_str(&contents)?)
    }

    async fn from_first_file(file: Option<impl AsRef<Path>>) -> Result<Config, ConfigError> {
        // if an explicit file is given, always use that one
        if let Some(f) = file {
            let path: &Path = f.as_ref();
            info!(?path, "using config file");
            return Config::from_file(f).await;
        }

        // for the global file we also ignore it when there are permission errors
        let global_path = Path::new("/etc/ntpd-rs/ntp.toml");
        if global_path.exists() {
            info!("using config file at default location `{:?}`", global_path);
            match Config::from_file(global_path).await {
                Err(ConfigError::Io(e)) if e.kind() == ErrorKind::PermissionDenied => {
                    info!("permission denied on global config file! using default config ...");
                }
                other => {
                    return other;
                }
            }
        }

        Ok(Config::default())
    }

    pub async fn from_args(
        file: Option<impl AsRef<Path>>,
        peers: Vec<PeerConfig>,
        servers: Vec<ServerConfig>,
    ) -> Result<Config, ConfigError> {
        let mut config = Config::from_first_file(file).await?;

        if !peers.is_empty() {
            if !config.peers.is_empty() {
                info!("overriding peers from configuration");
            }
            config.peers = peers;
        }

        if !servers.is_empty() {
            if !config.servers.is_empty() {
                info!("overriding servers from configuration");
            }
            config.servers = servers;
        }

        Ok(config)
    }

    /// Count potential number of peers in configuration
    fn count_peers(&self) -> usize {
        let mut count = 0;
        for peer in &self.peers {
            match peer {
                PeerConfig::Standard(_) => count += 1,
                PeerConfig::Nts(_) => count += 1,
                PeerConfig::Pool(config) => count += config.max_peers,
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
        if self.peers.is_empty() {
            warn!("No peers configured. Daemon will not change system time.");
            ok = false;
        }

        if self.count_peers() < self.synchronization.synchronization.minimum_agreeing_peers {
            warn!("Fewer peers configured than are required to agree on the current time. Daemon will not change system time.");
            ok = false;
        }

        ok
    }
}

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ObserveConfig {
    #[serde(default)]
    pub observation_path: Option<PathBuf>,
    #[serde(default = "default_observation_permissions")]
    pub observation_permissions: u32,
}

const fn default_observation_permissions() -> u32 {
    0o666
}

const fn default_configure_permissions() -> u32 {
    0o660
}

impl Default for ObserveConfig {
    fn default() -> Self {
        Self {
            observation_path: None,
            observation_permissions: default_observation_permissions(),
        }
    }
}

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ConfigureConfig {
    #[serde(default)]
    pub configure_path: Option<std::path::PathBuf>,
    #[serde(default = "default_configure_permissions")]
    pub configure_permissions: u32,
}

impl Default for ConfigureConfig {
    fn default() -> Self {
        Self {
            configure_path: None,
            configure_permissions: default_configure_permissions(),
        }
    }
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("io error while reading config: {0}")]
    Io(#[from] io::Error),
    #[error("config toml parsing error: {0}")]
    Toml(#[from] toml::de::Error),
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ntp_proto::{NtpDuration, StepThreshold};

    use super::*;

    #[test]
    fn test_config() {
        let config: Config =
            toml::from_str("[[peers]]\nmode = \"simple\"\naddress = \"example.com\"").unwrap();
        assert_eq!(
            config.peers,
            vec![PeerConfig::Standard(StandardPeerConfig {
                address: NormalizedAddress::new_unchecked("example.com", 123).into(),
            })]
        );
        assert!(config.observability.log_level.is_none());

        let config: Config = toml::from_str(
            "[observability]\nlog-level = \"info\"\n[[peers]]\nmode = \"simple\"\naddress = \"example.com\"",
        )
            .unwrap();
        assert_eq!(config.observability.log_level, Some(LogLevel::Info));
        assert_eq!(
            config.peers,
            vec![PeerConfig::Standard(StandardPeerConfig {
                address: NormalizedAddress::new_unchecked("example.com", 123).into(),
            })]
        );

        let config: Config = toml::from_str(
            "[[peers]]\nmode = \"simple\"\naddress = \"example.com\"\n[synchronization]\nsingle-step-panic-threshold = 0",
        )
            .unwrap();
        assert_eq!(
            config.peers,
            vec![PeerConfig::Standard(StandardPeerConfig {
                address: NormalizedAddress::new_unchecked("example.com", 123).into(),
            })]
        );
        assert_eq!(
            config
                .synchronization
                .synchronization
                .single_step_panic_threshold
                .forward,
            Some(NtpDuration::from_seconds(0.))
        );
        assert_eq!(
            config
                .synchronization
                .synchronization
                .single_step_panic_threshold
                .backward,
            Some(NtpDuration::from_seconds(0.))
        );

        let config: Config = toml::from_str(
            "[[peers]]\nmode = \"simple\"\naddress = \"example.com\"\n[synchronization]\nsingle-step-panic-threshold = \"inf\"",
        )
            .unwrap();
        assert_eq!(
            config.peers,
            vec![PeerConfig::Standard(StandardPeerConfig {
                address: NormalizedAddress::new_unchecked("example.com", 123).into(),
            })]
        );
        assert!(config
            .synchronization
            .synchronization
            .single_step_panic_threshold
            .forward
            .is_none());
        assert!(config
            .synchronization
            .synchronization
            .single_step_panic_threshold
            .backward
            .is_none());

        let config: Config = toml::from_str(
            r#"
            [[peers]]
            mode = "simple"
            address = "example.com"
            [peer-defaults]
            poll-interval-limits = { min = 5, max = 9 }
            initial-poll-interval = 5
            [observability]
            log-level = "info"
            observation-path = "/foo/bar/observe"
            observation-permissions = 0o567
            configure-path = "/foo/bar/configure"
            configure-permissions = 0o123
            "#,
        )
        .unwrap();
        assert!(config.observability.log_level.is_some());

        assert_eq!(
            config.observability.observe.observation_path,
            Some(PathBuf::from("/foo/bar/observe"))
        );
        assert_eq!(config.observability.observe.observation_permissions, 0o567);

        assert_eq!(
            config.observability.configure.configure_path,
            Some(PathBuf::from("/foo/bar/configure"))
        );
        assert_eq!(config.observability.configure.configure_permissions, 0o123);

        assert_eq!(
            config.peers,
            vec![PeerConfig::Standard(StandardPeerConfig {
                address: NormalizedAddress::new_unchecked("example.com", 123).into(),
            })]
        );

        let poll_interval_limits = config.peer_defaults.poll_interval_limits;
        assert_eq!(poll_interval_limits.min.as_log(), 5);
        assert_eq!(poll_interval_limits.max.as_log(), 9);

        assert_eq!(config.peer_defaults.initial_poll_interval.as_log(), 5);
    }

    #[test]
    fn clap_no_arguments() {
        let arguments: [String; 0] = [];
        let parsed_empty = NtpDaemonOptions::try_parse_from(arguments).unwrap();

        assert!(parsed_empty.config.is_none());
        assert!(parsed_empty.log_filter.is_none());
        assert_eq!(parsed_empty.action, NtpDaemonAction::Run);
    }

    #[test]
    fn clap_external_config() {
        let arguments = &["/usr/bin/ntp-daemon", "--config", "other.toml"];
        let parsed_empty = NtpDaemonOptions::try_parse_from(arguments).unwrap();

        assert_eq!(parsed_empty.config, Some("other.toml".into()));
        assert!(parsed_empty.log_filter.is_none());
        assert_eq!(parsed_empty.action, NtpDaemonAction::Run);

        let arguments = &["/usr/bin/ntp-daemon", "-c", "other.toml"];
        let parsed_empty = NtpDaemonOptions::try_parse_from(arguments).unwrap();

        assert_eq!(parsed_empty.config, Some("other.toml".into()));
        assert!(parsed_empty.log_filter.is_none());
        assert_eq!(parsed_empty.action, NtpDaemonAction::Run);
    }

    #[test]
    fn clap_log_filter() {
        let arguments = &["/usr/bin/ntp-daemon", "--log-filter", "debug"];
        let parsed_empty = NtpDaemonOptions::try_parse_from(arguments).unwrap();

        assert!(parsed_empty.config.is_none());
        assert_eq!(parsed_empty.log_filter.unwrap(), LogLevel::Debug);

        let arguments = &["/usr/bin/ntp-daemon", "-l", "debug"];
        let parsed_empty = NtpDaemonOptions::try_parse_from(arguments).unwrap();

        assert!(parsed_empty.config.is_none());
        assert_eq!(parsed_empty.log_filter.unwrap(), LogLevel::Debug);
    }

    #[test]
    fn toml_peers_invalid() {
        let config: Result<Config, _> = toml::from_str(
            r#"
            [[peers]]
            address = ":invalid:ipv6:123"
            "#,
        );

        assert!(config.is_err());
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
            #[allow(unused)]
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
            #[allow(unused)]
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
            enable-timestamps.rx-hardware = true
            enable-timestamps.tx-software = true
            "#,
        );

        let config = config.unwrap();

        let expected = InterfaceName::from_str("enp0s31f6").unwrap();
        assert_eq!(config.interface, Some(expected));

        assert!(config.enable_timestamps.rx_software);
        assert!(config.enable_timestamps.tx_software);
    }
}
