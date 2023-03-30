use serde::Deserialize;

use crate::{FrequencyTolerance, NtpDuration};

#[derive(Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AlgorithmConfig {
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
}

impl Default for AlgorithmConfig {
    fn default() -> Self {
        Self {
            min_cluster_survivors: default_min_cluster_survivors(),
            frequency_tolerance: default_frequency_tolerance(),
            distance_threshold: default_distance_threshold(),

            frequency_measurement_period: default_frequency_measurement_period(),
            spike_threshold: default_spike_threshold(),
        }
    }
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
