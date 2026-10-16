mod cli;
mod ntp_source;
mod server;

pub use cli::*;
use clock_steering::unix::UnixClock;
use ntp_proto::{NtpVersion, ProtocolVersion, SourceConfig, SynchronizationConfig};
pub use ntp_source::*;
use serde::{Deserialize, Deserializer, Serialize};
pub use server::*;
use statime_algo::LinkConfig;
use statime_config::{
    ConfigError, ConfigPath, Configurable, ConfigurableAtomic, PartialValue, RootConfig,
    SystemConfigSetting,
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

#[derive(Debug, Copy, Clone, Default)]
pub struct ClockConfig {
    pub clock: NtpClockWrapper,
    pub interface: Option<InterfaceName>,
    pub timestamp_mode: TimestampMode,
}

#[derive(Debug, Clone, Configurable)]
pub struct ObservabilityConfig {
    #[config(default)]
    pub log_level: Option<LogLevel>,
    #[config(default)]
    pub log_path: Option<PathBuf>,
    #[config(default)]
    pub log_path_metrics_exporter: Option<PathBuf>,
    #[config(default)]
    pub ansi_colors: Option<bool>,
    #[config(default)]
    pub observation_path: Option<PathBuf>,
    #[config(default = 0o666)]
    pub observation_permissions: u32,
    #[config(default="127.0.0.1:9975".parse().unwrap())]
    pub metrics_exporter_listen: SocketAddr,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        let mut partial = <Self as Configurable>::Node::default();
        partial.apply_defaults();
        partial.resolve(&mut ConfigPath::root()).unwrap()
    }
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

#[derive(Debug, Default, Configurable)]
pub struct Config {
    #[config(rename = "use-system-config", default)]
    #[allow(clippy::struct_field_names)]
    pub use_system_config: UseSystemConfig,
    #[config(rename = "source", default)]
    pub sources: Vec<NtpSourceConfig>,
    #[config(rename = "server", default)]
    pub servers: Vec<NtpServerConfig>,
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
