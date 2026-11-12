mod cli;
mod primitives;
mod server;
mod source;

pub use cli::*;
use clock_steering::unix::UnixClock;
use ntp_proto::{NtpVersion, ProtocolVersion};
pub use primitives::*;
use serde::{Deserialize, Deserializer, Serialize};
pub use server::*;
pub use source::*;
use statime_algo::LinkConfig;
use statime_config::{
    ConfigError, ConfigPath, Configurable, ConfigurableAtomic, InfiniteOr, NonNegative,
    PartialValue, Positive, RootConfig, SystemConfigSetting,
};
#[cfg(target_os = "linux")]
use statime_wire::{ClockAccuracy, ClockIdentity, ClockQuality};
use std::io;
use std::{
    fmt::Display,
    io::ErrorKind,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    str::FromStr,
};
use tracing::{info, warn};
use tracing_subscriber::layer::Filter;

use crate::daemon::nts_key_provider::KeysetConfig;

use super::{clock::NtpClockWrapper, tracing::LogLevel};

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

#[derive(Debug, Clone, Configurable)]
pub struct NtpSourceDefaults {
    #[config(rename = "minimum-poll-interval", default = Positive::unchecked_new(ConfigurableDuration {unit: Unit::Second, duration: 16.0}))]
    pub(crate) minimum_poll_interval: Positive<ConfigurableDuration>,
    #[config(rename = "minimum-poll-interval", default = Positive::unchecked_new(ConfigurableDuration {unit: Unit::Second, duration: 1024.0}))]
    pub(crate) maximum_poll_interval: Positive<ConfigurableDuration>,
    #[config(rename = "desired-error", default = Positive::unchecked_new(ConfigurableDuration {unit: Unit::Millisecond, duration: 1.0}))]
    pub(crate) desired_error: Positive<ConfigurableDuration>,
    // Experimental
    #[config(rename = "delay-decay-rate", default = Positive::unchecked_new(1.0/86400.0f64.sqrt()))]
    pub(crate) delay_decay_rate: Positive<f64>,
}

impl Default for NtpSourceDefaults {
    fn default() -> Self {
        let mut partial = <Self as Configurable>::Node::default();
        partial.apply_defaults();
        partial.resolve(&mut ConfigPath::root()).unwrap()
    }
}

#[derive(Debug, Clone, Configurable)]
pub struct CsptpSourceDefaults {
    #[config(default = 128)]
    pub(crate) domain: u8,
    #[config(rename = "poll-interval", default = Positive::unchecked_new(ConfigurableDuration {unit: Unit::Second, duration: 1.0}))]
    pub(crate) poll_interval: Positive<ConfigurableDuration>,
    #[config(rename = "response-interval", default = Positive::unchecked_new(ConfigurableDuration {unit: Unit::Second, duration: 1.0}))]
    pub(crate) response_interval: Positive<ConfigurableDuration>,
    // Experimental
    #[config(rename = "delay-decay-rate", default = Positive::unchecked_new(1.0/86400.0f64.sqrt()))]
    pub(crate) delay_decay_rate: Positive<f64>,
}

impl Default for CsptpSourceDefaults {
    fn default() -> Self {
        let mut partial = <Self as Configurable>::Node::default();
        partial.apply_defaults();
        partial.resolve(&mut ConfigPath::root()).unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Configurable)]
pub struct SystemClockConfig {
    #[config(default = true)]
    pub(crate) steered: bool,
    /// Threshold for a step at startup to trigger a warning.
    #[config(rename = "startup-jump-warning-threshold", default = PotentiallyAsymetricThreshold::Symmetric(InfiniteOr::Finite(NonNegative::unchecked_new(ConfigurableDuration { unit: Unit::Second, duration: 0.0 }))))]
    pub startup_jump_warning_threshold: PotentiallyAsymetricThreshold,
    /// Threshold for a step at startup to trigger an abort.
    #[config(rename = "startump-jump-abort-threshold", default = PotentiallyAsymetricThreshold::Asymmetric { forward: InfiniteOr::Infinite, backward: InfiniteOr::Finite(NonNegative::unchecked_new(ConfigurableDuration { unit: Unit::Day, duration: 1.0 }))})]
    pub startup_jump_abort_threshold: PotentiallyAsymetricThreshold,
    /// Threshold for a single step during normal operation to trigger a warning.
    #[config(rename = "single-jump-warning-threshold", default = PotentiallyAsymetricThreshold::Symmetric(InfiniteOr::Finite(NonNegative::unchecked_new(ConfigurableDuration { unit: Unit::Second, duration: 0.0 }))))]
    pub single_jump_warning_threshold: PotentiallyAsymetricThreshold,
    /// Threshold for a single step during normal operation to trigger an abort.
    #[config(rename = "single-jump-abort-threshold", default = PotentiallyAsymetricThreshold::Symmetric(InfiniteOr::Finite(NonNegative::unchecked_new(ConfigurableDuration { unit: Unit::Second, duration: 1000.0 }))))]
    pub single_jump_abort_threshold: PotentiallyAsymetricThreshold,
    /// Threshold for accumulated steps to trigger a warning.
    #[config(rename = "accumulated-jump-warning-threshold", default = InfiniteOr::Infinite)]
    pub accumulated_jump_warning_threshold: InfiniteOr<NonNegative<ConfigurableDuration>>,
    /// Threshold for accumulated steps to trigger an abort.
    #[config(rename = "accumulated-jump-abort-threshold", default = InfiniteOr::Infinite)]
    pub accumulated_jump_abort_threshold: InfiniteOr<NonNegative<ConfigurableDuration>>,
    /// Threshold on offset uncertainty after which a clock is considered out of startup (experimental)
    #[config(rename = "startup-end-threshold", default = Positive::unchecked_new(ConfigurableDuration { unit: Unit::Second, duration: 1.0 }))]
    pub startup_end_threshold: Positive<ConfigurableDuration>,
    /// How large does the offset need to be before we do a jump? (experimental)
    #[config(rename = "jump-threshold", default = Positive::unchecked_new(ConfigurableDuration { unit: Unit::Second, duration: 10.0 }))]
    pub jump_threshold: Positive<ConfigurableDuration>,
    /// How large does a jump need to be to happen, relative to the uncertainty
    /// of currently observed offset. (experimental)
    #[config(rename = "jump-certainty-threshold", default = NonNegative::unchecked_new(5.0))]
    pub jump_certainty_threshold: NonNegative<f64>,
    /// Amount of time to spread slewing over. This gives a typical time scale
    /// to reduce the offset error by about two thirds using slews. (experimental)
    #[config(rename = "slew-time-constant", default = Positive::unchecked_new(ConfigurableDuration { unit: Unit::Second, duration: 8.0 }))]
    pub slew_time_constant: Positive<ConfigurableDuration>,
    /// Offset and offset uncertainty below which we consider the clock synchronized. (experimental)
    #[config(rename = "synchronized-threshold", default = Positive::unchecked_new(ConfigurableDuration { unit: Unit::Second, duration: 1.0 }))]
    pub synchronized_threshold: Positive<ConfigurableDuration>,
    /// Initial estimate of the wander of the clock, as fractions of a second per second. (experimental)
    #[config(rename = "initial-wander", default = Positive::unchecked_new(1e-8))]
    pub initial_wander: Positive<f64>,
}

impl Default for SystemClockConfig {
    fn default() -> Self {
        let mut partial = <Self as Configurable>::Node::default();
        partial.apply_defaults();
        partial.resolve(&mut ConfigPath::root()).unwrap()
    }
}

impl SystemClockConfig {
    pub(crate) fn generate_clock_config(&self) -> statime_algo::ClockConfig {
        statime_algo::ClockConfig {
            startup_jump_warning_threshold: self.startup_jump_warning_threshold.into(),
            startup_jump_abort_threshold: self.startup_jump_abort_threshold.into(),
            single_jump_warning_threshold: self.single_jump_warning_threshold.into(),
            single_jump_abort_threshold: self.single_jump_abort_threshold.into(),
            accumulated_jump_warning_threshold: match self.accumulated_jump_warning_threshold {
                InfiniteOr::Infinite => None,
                InfiniteOr::Finite(value) => Some(value.into_inner().into()),
            },
            accumulated_jump_abort_threshold: match self.accumulated_jump_abort_threshold {
                InfiniteOr::Infinite => None,
                InfiniteOr::Finite(value) => Some(value.into_inner().into()),
            },
            startup_end_threshold: self.startup_end_threshold.into_inner().into(),
            jump_threshold: self.jump_threshold.into_inner().into(),
            jump_certainty_threshold: self.jump_certainty_threshold.into_inner(),
            slew_time_constant: self.slew_time_constant.into_inner().into(),
            synchronized_threshold: self.synchronized_threshold.into_inner().into(),
            initial_wander: self.initial_wander.into_inner(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Configurable)]
pub(crate) struct FilterConfig {
    /// Minimum number of sources that need to agree on the current time before
    /// we enable synchronization.
    #[config(rename = "minimum-agreeing-sources", default)]
    pub(crate) minimum_agreeing_sources: Option<Positive<usize>>,
    /// Size of the window of uncertainty to assume around source offset for
    /// judging whether it is a truechimer, based on the observed noise in the
    /// offset. (experimental)
    #[config(rename = "select-offset-uncertainty-window", default = NonNegative::unchecked_new(1.0))]
    pub(crate) select_offset_uncertainty_window: NonNegative<f64>,
    /// Size of the window of uncertainty to assume around source offset for
    /// judging whether it is a truechimer, based on the observed link delay
    /// noise. (experimental)
    #[config(rename = "select-link-uncertainty-window", default = NonNegative::unchecked_new(2.0))]
    pub(crate) select_link_uncertainty_window: NonNegative<f64>,
    /// Size of the window of uncertainty to assume around source offset for
    /// judging whether it is a truechimer, from potential asymmetry due to
    /// delay and root delay. (experimental)
    #[config(rename = "select-delay-uncertainty-window", default = NonNegative::unchecked_new(0.5))]
    pub(crate) select_delay_uncertainty_window: NonNegative<f64>,
    /// Maximum size of the window of uncertainty before we judge a source to
    /// be unsuitable for synchronization. (experimental)
    #[config(rename = "select-max-window-size", default = Positive::unchecked_new(ConfigurableDuration { unit: Unit::Second, duration: 1.0 }))]
    pub(crate) select_max_window_size: Positive<ConfigurableDuration>,
}

impl Default for FilterConfig {
    fn default() -> Self {
        let mut partial = <Self as Configurable>::Node::default();
        partial.apply_defaults();
        partial.resolve(&mut ConfigPath::root()).unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Configurable)]
pub struct NtsCookieKeys {
    /// Number of old keys to keep around
    #[config(rename = "old-key-count", default = Positive::unchecked_new(7))]
    pub old_key_count: Positive<usize>,
    /// How often to rotate keys
    #[config(rename = "key-rotation-interval", default = Positive::unchecked_new(ConfigurableDuration { unit: Unit::Day, duration: 1.0 }))]
    pub key_rotation_interval: Positive<ConfigurableDuration>,
    #[config(rename = "storage-path", default)]
    pub storage_path: Option<PathBuf>,
}

impl Default for NtsCookieKeys {
    fn default() -> Self {
        let mut partial = <Self as Configurable>::Node::default();
        partial.apply_defaults();
        partial.resolve(&mut ConfigPath::root()).unwrap()
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Configurable)]
pub struct CsptpConfig {
    /// Identity of the local instance.
    #[config(default)]
    pub identity: ConfigurableClockIdentity,
    /// Priority 1 value to use for the local clock.
    #[config(rename = "priority-1", default = 255)]
    pub priority_1: u8,
    /// Priority 2 value to use for the local clock.
    #[config(rename = "priority-1", default = 255)]
    pub priority_2: u8,
    #[config(rename = "clock-class", default = 248)]
    pub clock_class: u8,
    #[config(rename = "advertised-clock-accuracy", default = None)]
    pub advertised_clock_accuracy: Option<Positive<ConfigurableDuration>>,
    #[config(rename = "advertised-clock-deviation", default = Positive::unchecked_new(ConfigurableDuration { unit: Unit::Microsecond, duration: 300.0 }))]
    pub advertised_clock_deviation: Positive<ConfigurableDuration>,
    /// Whether the local time uses the ptp timescale.
    #[config(rename = "ptp-timescale", default = true)]
    pub ptp_timescale: bool,
    /// Whether the local time is traceable.
    #[config(rename = "time-traceable", default = false)]
    pub time_traceable: bool,
    /// Whether the local frequency is traceable.
    #[config(rename = "frequency-traceable", default = false)]
    pub frequency_traceable: bool,
}

#[cfg(target_os = "linux")]
impl Default for CsptpConfig {
    fn default() -> Self {
        let mut partial = <Self as Configurable>::Node::default();
        partial.apply_defaults();
        partial.resolve(&mut ConfigPath::root()).unwrap()
    }
}

// This struct allows us to derive ConfigurableAtomic.
#[cfg(target_os = "linux")]
#[derive(Default, Debug, Clone, PartialEq, Eq, ConfigurableAtomic)]
pub struct ConfigurableClockIdentity(ClockIdentity);

#[cfg(target_os = "linux")]
impl<'de> Deserialize<'de> for ConfigurableClockIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(ConfigurableClockIdentity(<ClockIdentity as Deserialize<
            'de,
        >>::deserialize(
            deserializer
        )?))
    }
}

#[cfg(target_os = "linux")]
impl Serialize for ConfigurableClockIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        <ClockIdentity as Serialize>::serialize(&self.0, serializer)
    }
}

#[cfg(feature = "seccomp")]
#[derive(
    Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ConfigurableAtomic,
)]
#[serde(rename_all = "kebab-case")]
pub enum SeccompMode {
    Kill,
    Log,
    #[default]
    Off,
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
    #[cfg(feature = "seccomp")]
    #[config(default)]
    pub seccomp: SeccompMode,
    #[config(rename = "source", default)]
    pub sources: Vec<SourceConfig>,
    #[config(rename = "server", default)]
    pub servers: Vec<ServerConfig>,
    pub ntp_source_defaults: NtpSourceDefaults,
    #[config(rename = "csptp-source-defaults")]
    pub csptp_source_defaults: CsptpSourceDefaults,
    #[config(rename = "system-clock")]
    pub system_clock: SystemClockConfig,
    #[config(rename = "nts-cookie-keys")]
    pub nts_cookie_keys: NtsCookieKeys,
    #[cfg(target_os = "linux")]
    #[config(rename = "csptp")]
    pub csptp: CsptpConfig,
    pub filter: FilterConfig,
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
        no_clock_steering: bool,
        sources: Vec<SourceConfig>,
        servers: Vec<ServerConfig>,
    ) -> Result<Config, ConfigError> {
        let mut config = Config::from_first_file(file.as_ref())?;

        if no_clock_steering {
            config.system_clock.steered = false;
        }

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
                SourceConfig::NtpServer(_) => count += 1,
                SourceConfig::NtpNtsServer(_) => count += 1,
                // FIXME: Do actual count when the configs are in place.
                SourceConfig::NtpPool(_) => count += 1,
                SourceConfig::NtpNtsPool(_) => count += 1,
                SourceConfig::Sock(_) => count += 1,
                #[cfg(feature = "pps")]
                SourceConfig::Pps(_) => {} // PPS sources don't count
                #[cfg(target_os = "linux")]
                SourceConfig::Csptp(_) => count += 1,
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

    pub(crate) fn generate_controller_config(&self) -> statime_algo::ControllerConfig {
        statime_algo::ControllerConfig {
            select_offset_uncertainty_window: self
                .filter
                .select_offset_uncertainty_window
                .into_inner(),
            select_link_uncertainty_window: self.filter.select_link_uncertainty_window.into_inner(),
            select_delay_uncertainty_window: self
                .filter
                .select_delay_uncertainty_window
                .into_inner(),
            select_max_window_size: self.filter.select_max_window_size.into_inner().into(),
            minimum_agreeing_sources: self
                .filter
                .minimum_agreeing_sources
                .map_or(3.min(self.count_sources()), Positive::into_inner),
        }
    }

    pub(crate) fn generate_keyset_config(&self) -> KeysetConfig {
        KeysetConfig {
            stale_key_count: self.nts_cookie_keys.old_key_count.into_inner(),
            key_rotation_interval: ConfigurableDuration::into_std_duration(
                self.nts_cookie_keys.key_rotation_interval,
            ),
            key_storage_path: self.nts_cookie_keys.storage_path.clone(),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn generate_csptp_config(&self) -> statime_csptp::CsptpConfig {
        let clock_accuracy = if let Some(duration) = self.csptp.advertised_clock_accuracy {
            let duration = duration.into_inner().seconds();
            if duration <= 1e-12 {
                ClockAccuracy::PS1
            } else if duration <= 2.5e-12 {
                ClockAccuracy::PS2_5
            } else if duration <= 10e-12 {
                ClockAccuracy::PS10
            } else if duration <= 25e-12 {
                ClockAccuracy::PS25
            } else if duration <= 100e-12 {
                ClockAccuracy::PS100
            } else if duration <= 250e-12 {
                ClockAccuracy::PS250
            } else if duration <= 1e-9 {
                ClockAccuracy::NS1
            } else if duration <= 2.5e-9 {
                ClockAccuracy::NS2_5
            } else if duration <= 10e-9 {
                ClockAccuracy::NS10
            } else if duration <= 25e-9 {
                ClockAccuracy::NS25
            } else if duration <= 100e-9 {
                ClockAccuracy::NS100
            } else if duration <= 250e-9 {
                ClockAccuracy::NS250
            } else if duration <= 1e-6 {
                ClockAccuracy::US1
            } else if duration <= 2.5e-6 {
                ClockAccuracy::US2_5
            } else if duration <= 10e-6 {
                ClockAccuracy::US10
            } else if duration <= 25e-6 {
                ClockAccuracy::US25
            } else if duration <= 100e-6 {
                ClockAccuracy::US100
            } else if duration <= 250e-6 {
                ClockAccuracy::US250
            } else if duration <= 1e-3 {
                ClockAccuracy::MS1
            } else if duration <= 2.5e-3 {
                ClockAccuracy::MS2_5
            } else if duration <= 10e-3 {
                ClockAccuracy::MS10
            } else if duration <= 25e-3 {
                ClockAccuracy::MS25
            } else if duration <= 100e-3 {
                ClockAccuracy::MS100
            } else if duration <= 250e-3 {
                ClockAccuracy::MS250
            } else if duration <= 1.0 {
                ClockAccuracy::S1
            } else if duration <= 10.0 {
                ClockAccuracy::S10
            } else {
                ClockAccuracy::SGT10
            }
        } else {
            ClockAccuracy::Unknown
        };

        let log_variance = self
            .csptp
            .advertised_clock_deviation
            .into_inner()
            .seconds()
            .log2()
            * 2.0;
        let scaled_log_variance = (log_variance * 256.0).ceil() as i16;

        statime_csptp::CsptpConfig {
            identity: self.csptp.identity.0,
            priority_1: self.csptp.priority_1,
            priority_2: self.csptp.priority_2,
            clock_quality: ClockQuality {
                clock_class: self.csptp.clock_class,
                clock_accuracy,
                offset_scaled_log_variance: scaled_log_variance.cast_unsigned(),
            },
            ptp_timescale: self.csptp.ptp_timescale,
            time_traceable: self.csptp.time_traceable,
            frequency_traceable: self.csptp.frequency_traceable,
        }
    }
}
