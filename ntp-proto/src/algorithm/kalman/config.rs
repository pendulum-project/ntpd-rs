use serde::Deserialize;

use crate::time_types::NtpDuration;

#[derive(Debug, Copy, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AlgorithmConfig {
    /// Probability bound below which we start moving towards decreasing
    /// our precision estimate. (probability, 0-1)
    #[serde(default = "default_precision_low_probability")]
    pub precision_low_probability: f64,
    /// Probability bound above which we start moving towards increasing
    /// our precision estimate. (probability, 0-1)
    #[serde(default = "default_precision_high_probability")]
    pub precision_high_probability: f64,
    /// Amount of hysteresis in changing the precision estimate. (count, 1+)
    #[serde(default = "default_precision_hysteresis")]
    pub precision_hysteresis: i32,
    /// Lower bound on the amount of effect our precision estimate
    /// has on the total noise estimate before we allow decreasing
    /// of the precision estimate. (weight, 0-1)
    #[serde(default = "default_precision_minimum_weight")]
    pub precision_minimum_weight: f64,

    /// Amount which a measurement contributes to the state, below
    /// which we start increasing the poll interval. (weight, 0-1)
    #[serde(default = "default_poll_interval_low_weight")]
    pub poll_interval_low_weight: f64,
    /// Amount which a measurement contributes to the state, above
    /// which we start decreasing the `poll_interval` interval. (weight, 0-1)
    #[serde(default = "default_poll_interval_high_weight")]
    pub poll_interval_high_weight: f64,
    /// Amount of hysteresis in changing the poll interval (count, 1+)
    #[serde(default = "default_poll_interval_hysteresis")]
    pub poll_interval_hysteresis: i32,
    /// Probability threshold for when a measurement is considered a
    /// significant enough outlier that we decide something weird is
    /// going on and we need to do more measurements. (probability, 0-1)
    #[serde(default = "default_poll_interval_step_threshold")]
    pub poll_interval_step_threshold: f64,

    /// Threshold (in number of standard deviations) above which
    /// measurements with a significantly larger network delay
    /// are rejected. (standard deviations, 0+)
    #[serde(default = "default_delay_outlier_threshold")]
    pub delay_outlier_threshold: f64,

    /// Initial estimate of the clock wander of the combination
    /// of our local clock and that of the source. (s/s^2)
    #[serde(default = "default_initial_wander")]
    pub initial_wander: f64,
    /// Initial uncertainty of the frequency difference between
    /// our clock and that of the source. (s/s)
    #[serde(default = "default_initial_frequency_uncertainty")]
    pub initial_frequency_uncertainty: f64,

    /// Maximum source uncertainty before we start disregarding it
    /// Note that this is combined uncertainty due to noise and
    /// possible asymmetry error (see also weights below). (seconds)
    #[serde(default = "default_maximum_source_uncertainty")]
    pub maximum_source_uncertainty: f64,
    /// Weight of statistical uncertainty when constructing
    /// overlap ranges. (standard deviations, 0+)
    #[serde(default = "default_range_statistical_weight")]
    pub range_statistical_weight: f64,
    /// Weight of delay uncertainty when constructing overlap
    /// ranges. (weight, 0-1)
    #[serde(default = "default_range_delay_weight")]
    pub range_delay_weight: f64,

    /// How far from 0 (in multiples of the uncertainty) should
    /// the offset be before we correct. (standard deviations, 0+)
    #[serde(default = "default_steer_offset_threshold")]
    pub steer_offset_threshold: f64,
    /// How many standard deviations do we leave after offset
    /// correction? (standard deviations, 0+)
    #[serde(default = "default_steer_offset_leftover")]
    pub steer_offset_leftover: f64,
    /// How far from 0 (in multiples of the uncertainty) should
    /// the frequency estimate be before we correct. (standard deviations, 0+)
    #[serde(default = "default_steer_frequency_threshold")]
    pub steer_frequency_threshold: f64,
    /// How many standard deviations do we leave after frequency
    /// correction? (standard deviations, 0+)
    #[serde(default = "default_steer_frequency_leftover")]
    pub steer_frequency_leftover: f64,
    /// From what offset should we step the clock instead of
    /// trying to adjust gradually? (seconds, 0+)
    #[serde(default = "default_step_threshold")]
    pub step_threshold: f64,
    /// What is the maximum frequency offset during a slew (s/s)
    #[serde(default = "default_slew_maximum_frequency_offset")]
    pub slew_maximum_frequency_offset: f64,
    /// What is the minimum duration of a slew (s)
    #[serde(default = "default_slew_minimum_duration")]
    pub slew_minimum_duration: f64,

    /// Absolute maximum frequency correction (s/s)
    #[serde(default = "default_maximum_frequency_steer")]
    pub maximum_frequency_steer: f64,

    /// Ignore a servers advertised dispersion when synchronizing.
    /// Can improve synchronization quality with servers reporting
    /// overly conservative root dispersion.
    #[serde(default)]
    pub ignore_server_dispersion: bool,

    /// Threshold for detecting external clock meddling
    #[serde(default = "default_meddling_threshold")]
    pub meddling_threshold: NtpDuration,
}

impl Default for AlgorithmConfig {
    fn default() -> Self {
        Self {
            precision_low_probability: default_precision_low_probability(),
            precision_high_probability: default_precision_high_probability(),
            precision_hysteresis: default_precision_hysteresis(),
            precision_minimum_weight: default_precision_minimum_weight(),

            poll_interval_low_weight: default_poll_interval_low_weight(),
            poll_interval_high_weight: default_poll_interval_high_weight(),
            poll_interval_hysteresis: default_poll_interval_hysteresis(),
            poll_interval_step_threshold: default_poll_interval_step_threshold(),

            delay_outlier_threshold: default_delay_outlier_threshold(),

            initial_wander: default_initial_wander(),
            initial_frequency_uncertainty: default_initial_frequency_uncertainty(),

            maximum_source_uncertainty: default_maximum_source_uncertainty(),
            range_statistical_weight: default_range_statistical_weight(),
            range_delay_weight: default_range_delay_weight(),

            steer_offset_threshold: default_steer_offset_threshold(),
            steer_offset_leftover: default_steer_offset_leftover(),
            steer_frequency_threshold: default_steer_frequency_threshold(),
            steer_frequency_leftover: default_steer_frequency_leftover(),
            step_threshold: default_step_threshold(),
            slew_maximum_frequency_offset: default_slew_maximum_frequency_offset(),
            slew_minimum_duration: default_slew_minimum_duration(),

            maximum_frequency_steer: default_maximum_frequency_steer(),

            ignore_server_dispersion: false,

            meddling_threshold: default_meddling_threshold(),
        }
    }
}

fn default_precision_low_probability() -> f64 {
    1. / 3.
}

fn default_precision_high_probability() -> f64 {
    2. / 3.
}

fn default_precision_hysteresis() -> i32 {
    16
}

fn default_precision_minimum_weight() -> f64 {
    0.1
}

fn default_poll_interval_low_weight() -> f64 {
    0.4
}

fn default_poll_interval_high_weight() -> f64 {
    0.6
}

fn default_poll_interval_hysteresis() -> i32 {
    16
}

fn default_poll_interval_step_threshold() -> f64 {
    1e-6
}

fn default_delay_outlier_threshold() -> f64 {
    5.
}

fn default_initial_wander() -> f64 {
    1e-8
}

fn default_initial_frequency_uncertainty() -> f64 {
    100e-6
}

fn default_maximum_source_uncertainty() -> f64 {
    0.250
}

fn default_range_statistical_weight() -> f64 {
    2.
}

fn default_range_delay_weight() -> f64 {
    0.25
}

fn default_steer_offset_threshold() -> f64 {
    2.0
}

fn default_steer_offset_leftover() -> f64 {
    1.0
}

fn default_steer_frequency_threshold() -> f64 {
    0.0
}

fn default_steer_frequency_leftover() -> f64 {
    0.0
}

fn default_step_threshold() -> f64 {
    0.010
}

fn default_slew_maximum_frequency_offset() -> f64 {
    200e-6
}

fn default_maximum_frequency_steer() -> f64 {
    495e-6
}

fn default_slew_minimum_duration() -> f64 {
    8.0
}

fn default_meddling_threshold() -> NtpDuration {
    NtpDuration::from_seconds(5.)
}
