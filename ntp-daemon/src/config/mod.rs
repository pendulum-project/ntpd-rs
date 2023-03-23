pub mod dynamic;
pub mod format;
mod peer;
mod server;
pub mod subnet;

use ntp_os_clock::DefaultNtpClock;
use ntp_udp::{EnableTimestamps, InterfaceName};
pub use peer::*;
pub use server::*;

use clap::Parser;
use ntp_proto::{DefaultTimeSyncController, SystemConfig, TimeSyncController};
use serde::{de, Deserialize, Deserializer};
use std::{
    io::ErrorKind,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;
use tokio::{fs::read_to_string, io};
use tracing::{info, warn};
use tracing_subscriber::filter::EnvFilter;

use crate::spawn::PeerId;

use self::format::LogFormat;

fn deserialize_clock<'de, D>(deserializer: D) -> Result<DefaultNtpClock, D::Error>
where
    D: Deserializer<'de>,
{
    let data: Option<PathBuf> = Deserialize::deserialize(deserializer)?;

    if let Some(path) = data {
        DefaultNtpClock::from_path(&path).map_err(|e| serde::de::Error::custom(e.to_string()))
    } else {
        Ok(DefaultNtpClock::realtime())
    }
}

fn default_ntp_clock() -> DefaultNtpClock {
    DefaultNtpClock::realtime()
}

fn deserialize_option_interface_name<'de, D>(
    deserializer: D,
) -> Result<Option<[i8; libc::IFNAMSIZ]>, D::Error>
where
    D: Deserializer<'de>,
{
    let data: Option<&str> = Deserialize::deserialize(deserializer)?;

    Ok(data.map(|string| {
        let mut it = string.bytes().map(|b| b as i8);
        std::array::from_fn(|_| it.next().unwrap_or_default())
    }))
}

fn deserialize_option_env_filter<'de, D>(deserializer: D) -> Result<Option<EnvFilter>, D::Error>
where
    D: Deserializer<'de>,
{
    let data: Option<String> = Deserialize::deserialize(deserializer)?;

    if let Some(dirs) = data {
        // allow us to recognise configs with an empty log filter directive
        if dirs.is_empty() {
            Ok(None)
        } else {
            Ok(Some(EnvFilter::try_new(dirs).map_err(de::Error::custom)?))
        }
    } else {
        Ok(None)
    }
}

fn parse_env_filter(input: &str) -> Result<Arc<EnvFilter>, tracing_subscriber::filter::ParseError> {
    EnvFilter::builder()
        .with_regex(false)
        .parse(input)
        .map(Arc::new)
}

#[derive(Parser, Debug)]
pub struct CmdArgs {
    #[arg(
        short,
        long = "peer",
        global = true,
        value_name = "SERVER",
        value_parser = PeerConfig::try_from_str,
        help = "Override the peers in the configuration file"
    )]
    pub peers: Vec<PeerConfig>,

    #[arg(
        short,
        long,
        global = true,
        value_name = "FILE",
        help = "Path of the configuration file"
    )]
    pub config: Option<PathBuf>,

    #[arg(
        long,
        short,
        global = true,
        value_name = "FILTER",
        value_parser = parse_env_filter,
        env = "NTP_LOG",
        help = "Filter to apply to log messages"
    )]
    pub log_filter: Option<Arc<EnvFilter>>,

    #[arg(
        long,
        global = true,
        value_name = "FORMAT",
        env = "NTP_LOG_FORMAT",
        help = "Output format for logs (full, compact, pretty, json)"
    )]
    pub log_format: Option<LogFormat>,

    #[arg(
        short,
        long = "server",
        global = true,
        value_name = "ADDR",
        value_parser = ServerConfig::try_from_str,
        help = "Override the servers to run from the configuration file"
    )]
    pub servers: Vec<ServerConfig>,
}

fn deserialize_ntp_clock<'de, D>(deserializer: D) -> Result<DefaultNtpClock, D::Error>
where
    D: Deserializer<'de>,
{
    let data: Option<PathBuf> = Deserialize::deserialize(deserializer)?;

    if let Some(_path_buf) = data {
        Err(serde::de::Error::custom("not yet supported"))
    } else {
        Ok(DefaultNtpClock::default())
    }
}

#[derive(Deserialize, Debug, Copy, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ClockConfig {
    #[serde(deserialize_with = "deserialize_ntp_clock", default)]
    pub clock: DefaultNtpClock,
    pub interface: Option<InterfaceName>,
    pub enable_timestamps: EnableTimestamps,
}

#[derive(Deserialize, Debug, Default, Copy, Clone)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CombinedSystemConfig {
    #[serde(flatten)]
    pub system: SystemConfig,
    #[serde(deserialize_with = "deserialize_clock", default = "default_ntp_clock")]
    pub clock: DefaultNtpClock,
    #[serde(deserialize_with = "deserialize_option_interface_name", default)]
    pub interface: Option<[i8; libc::IFNAMSIZ]>,
    #[serde(flatten)]
    pub algorithm: <DefaultTimeSyncController<DefaultNtpClock, PeerId> as TimeSyncController<
        DefaultNtpClock,
        PeerId,
    >>::AlgorithmConfig,
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    #[serde(alias = "peer")]
    pub peers: Vec<PeerConfig>,
    #[serde(alias = "server", default)]
    pub servers: Vec<ServerConfig>,
    #[serde(alias = "nts-ke-server", default)]
    pub nts_ke: Option<NtsKeConfig>,
    #[serde(default)]
    pub system: CombinedSystemConfig,
    #[serde(deserialize_with = "deserialize_option_env_filter", default)]
    pub log_filter: Option<EnvFilter>,
    #[serde(default)]
    pub log_format: LogFormat,
    #[cfg(feature = "sentry")]
    #[serde(default)]
    pub sentry: SentryConfig,
    #[serde(default)]
    pub observe: ObserveConfig,
    #[serde(default)]
    pub configure: ConfigureConfig,
    #[serde(default)]
    pub keyset: KeysetConfig,
    #[serde(default)]
    pub clock: ClockConfig,
}

const fn default_observe_permissions() -> u32 {
    0o777
}

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ObserveConfig {
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default = "default_observe_permissions")]
    pub mode: u32,
}

const fn default_configure_permissions() -> u32 {
    0o770
}

impl Default for ObserveConfig {
    fn default() -> Self {
        Self {
            path: None,
            mode: default_observe_permissions(),
        }
    }
}

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ConfigureConfig {
    #[serde(default)]
    pub path: Option<std::path::PathBuf>,
    #[serde(default = "default_configure_permissions")]
    pub mode: u32,
}

impl Default for ConfigureConfig {
    fn default() -> Self {
        Self {
            path: None,
            mode: default_configure_permissions(),
        }
    }
}

#[cfg(feature = "sentry")]
#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SentryConfig {
    pub dsn: Option<String>,
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f32,
}

#[cfg(feature = "sentry")]
fn default_sample_rate() -> f32 {
    0.0
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("io error while reading config: {0}")]
    Io(#[from] io::Error),
    #[error("config toml parsing error: {0}")]
    Toml(#[from] toml::de::Error),
}

impl Config {
    async fn from_file(file: impl AsRef<Path>) -> Result<Config, ConfigError> {
        let meta = std::fs::metadata(&file).unwrap();
        let perm = meta.permissions();

        if perm.mode() & libc::S_IWOTH != 0 {
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
        match Config::from_file("/etc/ntpd-rs/ntp.toml").await {
            Err(ConfigError::Io(e))
                if e.kind() == ErrorKind::NotFound || e.kind() == ErrorKind::PermissionDenied => {}
            other => {
                info!("using global config file at default location `/etc/ntpd-rs/ntp.toml`");
                return other;
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

    /// Check that the config is reasonable. This function may panic if the
    /// configuration is egregious, although it doesn't do so currently.
    pub fn check(&self) {
        // Note: since we only check once logging is fully configured,
        // using those fields should always work. This is also
        // probably a good policy in general (config should always work
        // but we may panic here to protect the user from themselves)
        if self.peers.is_empty() {
            warn!("No peers configured. Daemon will not do anything.");
        }

        if self.peers.len() < self.system.system.min_intersection_survivors {
            warn!("Fewer peers configured than are required to agree on the current time. Daemon will not do anything.");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, str::FromStr};

    use ntp_proto::{NtpDuration, StepThreshold};

    use super::*;

    #[test]
    fn test_config() {
        let config: Config = toml::from_str("[[peers]]\naddr = \"example.com\"").unwrap();
        assert_eq!(
            config.peers,
            vec![PeerConfig::Standard(StandardPeerConfig {
                addr: NormalizedAddress::new_unchecked("example.com", 123),
            })]
        );

        let config: Config =
            toml::from_str("log-filter = \"\"\n[[peers]]\naddr = \"example.com\"").unwrap();
        assert!(config.log_filter.is_none());
        assert_eq!(
            config.peers,
            vec![PeerConfig::Standard(StandardPeerConfig {
                addr: NormalizedAddress::new_unchecked("example.com", 123),
            })]
        );

        let config: Config =
            toml::from_str("log-filter = \"info\"\n[[peers]]\naddr = \"example.com\"").unwrap();
        assert!(config.log_filter.is_some());
        assert_eq!(
            config.peers,
            vec![PeerConfig::Standard(StandardPeerConfig {
                addr: NormalizedAddress::new_unchecked("example.com", 123),
            })]
        );

        let config: Config =
            toml::from_str("[[peers]]\naddr = \"example.com\"\n[system]\npanic-threshold = 0")
                .unwrap();
        assert_eq!(
            config.peers,
            vec![PeerConfig::Standard(StandardPeerConfig {
                addr: NormalizedAddress::new_unchecked("example.com", 123),
            })]
        );
        assert_eq!(
            config.system.system.panic_threshold.forward,
            Some(NtpDuration::from_seconds(0.))
        );
        assert_eq!(
            config.system.system.panic_threshold.backward,
            Some(NtpDuration::from_seconds(0.))
        );

        let config: Config = toml::from_str(
            "[[peers]]\naddr = \"example.com\"\n[system]\npanic-threshold = \"inf\"",
        )
        .unwrap();
        assert_eq!(
            config.peers,
            vec![PeerConfig::Standard(StandardPeerConfig {
                addr: NormalizedAddress::new_unchecked("example.com", 123),
            })]
        );
        assert!(config.system.system.panic_threshold.forward.is_none());
        assert!(config.system.system.panic_threshold.backward.is_none());

        let config: Config = toml::from_str(
            r#"
            log-filter = "info"
            log-format = "full"
            [[peers]]
            addr = "example.com"
            [observe]
            path = "/foo/bar/observe"
            mode = 0o567
            [configure]
            path = "/foo/bar/configure"
            mode = 0o123
            "#,
        )
        .unwrap();
        assert!(config.log_filter.is_some());

        assert_eq!(config.observe.path, Some(PathBuf::from("/foo/bar/observe")));
        assert_eq!(config.observe.mode, 0o567);

        assert_eq!(
            config.configure.path,
            Some(PathBuf::from("/foo/bar/configure"))
        );
        assert_eq!(config.configure.mode, 0o123);

        assert_eq!(
            config.peers,
            vec![PeerConfig::Standard(StandardPeerConfig {
                addr: NormalizedAddress::new_unchecked("example.com", 123),
            })]
        );
    }

    #[cfg(feature = "sentry")]
    #[test]
    fn test_sentry_config() {
        let config: Config = toml::from_str("[[peers]]\naddr = \"example.com\"").unwrap();
        assert!(config.sentry.dsn.is_none());

        let config: Config =
            toml::from_str("[[peers]]\naddr = \"example.com\"\n[sentry]\ndsn = \"abc\"").unwrap();
        assert_eq!(config.sentry.dsn, Some("abc".into()));

        let config: Config = toml::from_str(
            "[[peers]]\naddr = \"example.com\"\n[sentry]\ndsn = \"abc\"\nsample-rate = 0.5",
        )
        .unwrap();
        assert_eq!(config.sentry.dsn, Some("abc".into()));
        assert!((config.sentry.sample_rate - 0.5).abs() < 1e-9);
    }

    #[test]
    fn clap_no_arguments() {
        use clap::Parser;

        let arguments: [OsString; 0] = [];
        let parsed_empty = CmdArgs::try_parse_from(arguments).unwrap();

        assert!(parsed_empty.peers.is_empty());
        assert!(parsed_empty.config.is_none());
        assert!(parsed_empty.log_filter.is_none());
    }

    #[test]
    fn clap_external_config() {
        use clap::Parser;

        let arguments = &["--", "--config", "other.toml"];
        let parsed_empty = CmdArgs::try_parse_from(arguments).unwrap();

        assert!(parsed_empty.peers.is_empty());
        assert_eq!(parsed_empty.config, Some("other.toml".into()));
        assert!(parsed_empty.log_filter.is_none());

        let arguments = &["--", "-c", "other.toml"];
        let parsed_empty = CmdArgs::try_parse_from(arguments).unwrap();

        assert!(parsed_empty.peers.is_empty());
        assert_eq!(parsed_empty.config, Some("other.toml".into()));
        assert!(parsed_empty.log_filter.is_none());
    }

    #[test]
    fn clap_log_filter() {
        use clap::Parser;

        let arguments = &["--", "--log-filter", "debug"];
        let parsed_empty = CmdArgs::try_parse_from(arguments).unwrap();

        assert!(parsed_empty.peers.is_empty());
        assert!(parsed_empty.config.is_none());
        assert_eq!(parsed_empty.log_filter.unwrap().to_string(), "debug");

        let arguments = &["--", "-l", "debug"];
        let parsed_empty = CmdArgs::try_parse_from(arguments).unwrap();

        assert!(parsed_empty.peers.is_empty());
        assert!(parsed_empty.config.is_none());
        assert_eq!(parsed_empty.log_filter.unwrap().to_string(), "debug");
    }

    #[test]
    fn clap_peers() {
        use clap::Parser;

        let arguments = &["--", "--peer", "foo.nl"];
        let parsed_empty = CmdArgs::try_parse_from(arguments).unwrap();

        assert_eq!(
            parsed_empty.peers,
            vec![PeerConfig::Standard(StandardPeerConfig {
                addr: NormalizedAddress::new_unchecked("foo.nl", 123),
            })]
        );
        assert!(parsed_empty.config.is_none());
        assert!(parsed_empty.log_filter.is_none());

        let arguments = &["--", "--peer", "foo.rs", "-p", "spam.nl:123"];
        let parsed_empty = CmdArgs::try_parse_from(arguments).unwrap();

        assert_eq!(
            parsed_empty.peers,
            vec![
                PeerConfig::Standard(StandardPeerConfig {
                    addr: NormalizedAddress::new_unchecked("foo.rs", 123),
                }),
                PeerConfig::Standard(StandardPeerConfig {
                    addr: NormalizedAddress::new_unchecked("spam.nl", 123),
                }),
            ]
        );
        assert!(parsed_empty.config.is_none());
        assert!(parsed_empty.log_filter.is_none());
    }

    #[test]
    fn clap_peers_invalid() {
        let arguments = &["--", "--peer", ":invalid:ipv6:123"];
        assert!(CmdArgs::try_parse_from(arguments).is_err());
    }

    #[test]
    fn toml_peers_invalid() {
        let config: Result<Config, _> = toml::from_str(
            r#"
            [[peers]]
            addr = ":invalid:ipv6:123"
            "#,
        );

        assert!(config.is_err());
    }

    #[test]
    fn system_config_accumulated_threshold() {
        let config: Result<SystemConfig, _> = toml::from_str(
            r#"
            accumulated-threshold = 0
            "#,
        );

        let config = config.unwrap();
        assert!(config.accumulated_threshold.is_none());

        let config: Result<SystemConfig, _> = toml::from_str(
            r#"
            accumulated-threshold = 1000
            "#,
        );

        let config = config.unwrap();
        assert_eq!(
            config.accumulated_threshold,
            Some(NtpDuration::from_seconds(1000.0))
        );
    }

    #[test]
    fn system_config_startup_panic_threshold() {
        let config: Result<SystemConfig, _> = toml::from_str(
            r#"
            startup-panic-threshold = { forward = 10, backward = 20 }
            "#,
        );

        let config = config.unwrap();
        assert_eq!(
            config.startup_panic_threshold.forward,
            Some(NtpDuration::from_seconds(10.0))
        );
        assert_eq!(
            config.startup_panic_threshold.backward,
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
        let config: Result<SystemConfig, _> = toml::from_str(
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
