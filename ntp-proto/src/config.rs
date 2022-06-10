use serde::{Deserialize, Deserializer};

use crate::{time_types::FrequencyTolerance, NtpDuration};

fn deserialize_option_threshold<'de, D>(deserializer: D) -> Result<Option<NtpDuration>, D::Error>
where
    D: Deserializer<'de>,
{
    let duration: NtpDuration = Deserialize::deserialize(deserializer)?;
    Ok(if duration == NtpDuration::ZERO {
        None
    } else {
        Some(duration)
    })
}

#[derive(Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub struct SystemConfig {
    /// Minimum number of survivors needed to be able to discipline the system clock.
    /// More survivors (so more servers from which to get the time) means a more accurate time.
    ///
    /// The spec notes (CMIN was renamed to MIN_INTERSECTION_SURVIVORS in our implementation):
    ///
    /// > CMIN defines the minimum number of servers consistent with the correctness requirements.
    /// > Suspicious operators would set CMIN to ensure multiple redundant servers are available for the
    /// > algorithms to mitigate properly. However, for historic reasons the default value for CMIN is one.
    #[serde(default = "default_min_intersection_survivors")]
    pub min_intersection_survivors: usize,

    /// Number of survivors that the cluster_algorithm tries to keep.
    ///
    /// The code skeleton notes that the goal is to give the cluster algorithm something to chew on.
    /// The spec itself does not say anything about how this variable is chosen, or why it exists
    /// (but it does define the use of this variable)
    ///
    /// Because the input can have fewer than 3 survivors, the MIN_CLUSTER_SURVIVORS
    /// is not an actual lower bound on the number of survivors.
    #[serde(default = "default_min_cluster_survivors")]
    pub min_cluster_survivors: usize,

    /// How much the time is allowed to drift (worst-case) per second.
    /// The drift caused by our frequency not exactly matching the real time
    #[serde(default = "default_frequency_tolerance")]
    pub frequency_tolerance: FrequencyTolerance,

    /// A distance error occurs if the root distance exceeds the
    /// distance threshold plus an increment equal to one poll interval.
    #[serde(default = "default_distance_threshold")]
    pub distance_threshold: NtpDuration,

    /// The amount of time to use to measure the system clocks frequency error
    /// on startup. Longer time periods give a more accurate initial estimate,
    /// but it will take longer for the clock to be fully synchronized
    #[serde(default = "default_frequency_measurement_period")]
    pub frequency_measurement_period: NtpDuration,

    /// The amount of time before a spike (a time difference greater than 0.125s)
    /// is considered real and not the result of a transient network condition
    #[serde(default = "default_spike_threshold")]
    pub spike_threshold: NtpDuration,

    /// The maximum amount the system clock is allowed to change in a single go
    /// before we conclude something is seriously wrong. This is used to limit
    /// the changes to the clock to reasonable ammounts, and stop issues with
    /// remote servers from causing us to drift too far.
    ///
    /// Note that this is not used during startup. To limit system clock changes
    /// during startup, use startup_panic_threshold
    #[serde(
        deserialize_with = "deserialize_option_threshold",
        default = "default_panic_threshold"
    )]
    pub panic_threshold: Option<NtpDuration>,

    /// The maximum amount the system clock is allowed to change during startup.
    /// This can be used to limit the impact of bad servers if the system clock
    /// is known to be reasonable on startup
    #[serde(deserialize_with = "deserialize_option_threshold", default)]
    pub startup_panic_threshold: Option<NtpDuration>,
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            // TODO this should be 4 in production?!
            min_intersection_survivors: default_min_intersection_survivors(),
            min_cluster_survivors: default_min_cluster_survivors(),
            frequency_tolerance: default_frequency_tolerance(),
            distance_threshold: default_distance_threshold(),

            frequency_measurement_period: default_frequency_measurement_period(),
            spike_threshold: default_spike_threshold(),
            panic_threshold: default_panic_threshold(),
            startup_panic_threshold: None,
        }
    }
}

fn default_min_intersection_survivors() -> usize {
    1
}

fn default_min_cluster_survivors() -> usize {
    3
}

fn default_frequency_tolerance() -> FrequencyTolerance {
    FrequencyTolerance::ppm(15)
}

fn default_distance_threshold() -> NtpDuration {
    NtpDuration::ONE
}

fn default_frequency_measurement_period() -> NtpDuration {
    NtpDuration::from_seconds(900.)
}

fn default_spike_threshold() -> NtpDuration {
    NtpDuration::from_seconds(900.)
}

fn default_panic_threshold() -> Option<NtpDuration> {
    Some(NtpDuration::from_seconds(1000.))
}
