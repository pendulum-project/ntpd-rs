use serde::Deserialize;

#[derive(Debug, Copy, Clone, Deserialize)]
pub struct AlgorithmConfig {
    /// Probability bound below which we start moving towards decreasing
    /// our precision estimate.
    #[serde(default = "default_precision_low_probability")]
    pub precision_low_probability: f64,
    /// Probability bound above which we start moving towards increasing
    /// our precision estimate
    #[serde(default = "default_precision_high_probability")]
    pub precision_high_probability: f64,
    /// Ammount of histeresis in changeing the precision estimate
    #[serde(default = "default_precision_histeresis")]
    pub precision_histeresis: i32,
    /// Lower bound on the ammount of effect our precision estimate
    /// has on the total noise estimate before we allow decreasing
    /// of the precision estimate
    #[serde(default = "default_precision_min_weight")]
    pub precision_min_weight: f64,

    /// Ammount which a measurement contributes to the state, below
    /// which we start increasing the poll interval
    #[serde(default = "default_poll_low_weight")]
    pub poll_low_weight: f64,
    /// Ammount which a measurement contributes to the state, above
    /// which we start decreasing the poll interval
    #[serde(default = "default_poll_high_weight")]
    pub poll_high_weight: f64,
    /// Ammount of histeresis in changeing the poll interval
    #[serde(default = "default_poll_histeresis")]
    pub poll_histeresis: i32,
    /// Probability threshold for when a measurement is considered a
    /// significant enough outlier that we decide something weird is
    /// going on and we need to do more measurements.
    #[serde(default = "default_poll_jump_threshold")]
    pub poll_jump_threshold: f64,

    /// Threshold (in number of standard deviations) above which
    /// measurements with a significantly larger network delay
    /// are rejected.
    #[serde(default = "default_delay_outlier_threshold")]
    pub delay_outlier_threshold: f64,

    /// Initial estimate of the clock wander of the combination
    /// of our local clock and that of the peer
    #[serde(default = "default_initial_wander")]
    pub initial_wander: f64,
    /// Initail uncertainty of the frequency difference between
    /// our clock and that of the peer.
    #[serde(default = "default_initial_frequency_uncertainty")]
    pub initial_frequency_uncertainty: f64,

    /// Maximum peer uncertainty before we start disregarding it
    /// Note that this is combined uncertainty due to noise and
    /// possible assymetry error (see also weights below)
    #[serde(default = "default_max_peer_uncertainty")]
    pub max_peer_uncertainty: f64,
    /// Weight of statistical uncertainty when constructing
    /// overlap ranges
    #[serde(default = "default_range_statistical_weight")]
    pub range_statistical_weight: f64,
    /// Weight of delay uncertainty when constructing overlap
    /// ranges
    #[serde(default = "default_range_delay_weight")]
    pub range_delay_weight: f64,

    /// How far from 0 (in multiples of the uncertainty) should
    /// the offset be before we correct
    #[serde(default = "default_steer_offset_threshold")]
    pub steer_offset_threshold: f64,
    /// How many standard deviations do we leave after offset
    /// correction?
    #[serde(default = "default_steer_offset_leftover")]
    pub steer_offset_leftover: f64,
    /// How far from 0 (in multiples of the uncertainty) should
    /// the frequency estimate be before we correct
    #[serde(default = "default_steer_frequency_threshold")]
    pub steer_frequency_threshold: f64,
    /// How many standard deviations do we leave after frequency
    /// correction?
    #[serde(default = "default_steer_frequency_leftover")]
    pub steer_frequency_leftover: f64,
    /// From what offset should we jump the clock instead of
    /// trying to adjust gradually?
    #[serde(default = "default_jump_threshold")]
    pub jump_threshold: f64,
    /// What is the maximum frequency offset during a slew (in s/s)
    #[serde(default = "default_slew_max_frequency_offset")]
    pub slew_max_frequency_offset: f64,
    /// What is the minimum duration of a slew (in s)
    #[serde(default = "default_slew_min_duration")]
    pub slew_min_duration: f64,

    /// Ignore a servers advertised dispersion when synchronizing.
    /// Can improve synchronization quality with servers reporting
    /// overly conservative root dispersion.
    #[serde(default)]
    pub ignore_server_dispersion: bool,
}

impl Default for AlgorithmConfig {
    fn default() -> Self {
        Self {
            precision_low_probability: default_precision_low_probability(),
            precision_high_probability: default_precision_high_probability(),
            precision_histeresis: default_precision_histeresis(),
            precision_min_weight: default_precision_min_weight(),

            poll_low_weight: default_poll_low_weight(),
            poll_high_weight: default_poll_high_weight(),
            poll_histeresis: default_poll_histeresis(),
            poll_jump_threshold: default_poll_jump_threshold(),

            delay_outlier_threshold: default_delay_outlier_threshold(),

            initial_wander: default_initial_wander(),
            initial_frequency_uncertainty: default_initial_frequency_uncertainty(),

            max_peer_uncertainty: default_max_peer_uncertainty(),
            range_statistical_weight: default_range_statistical_weight(),
            range_delay_weight: default_range_delay_weight(),

            steer_offset_threshold: default_steer_offset_threshold(),
            steer_offset_leftover: default_steer_offset_leftover(),
            steer_frequency_threshold: default_steer_frequency_threshold(),
            steer_frequency_leftover: default_steer_frequency_leftover(),
            jump_threshold: default_jump_threshold(),
            slew_max_frequency_offset: default_slew_max_frequency_offset(),
            slew_min_duration: default_slew_min_duration(),

            ignore_server_dispersion: false,
        }
    }
}

fn default_precision_low_probability() -> f64 {
    1. / 3.
}

fn default_precision_high_probability() -> f64 {
    2. / 3.
}

fn default_precision_histeresis() -> i32 {
    16
}

fn default_precision_min_weight() -> f64 {
    0.1
}

fn default_poll_low_weight() -> f64 {
    0.4
}

fn default_poll_high_weight() -> f64 {
    0.6
}

fn default_poll_histeresis() -> i32 {
    16
}

fn default_poll_jump_threshold() -> f64 {
    1e-6
}

fn default_delay_outlier_threshold() -> f64 {
    5.
}

fn default_initial_wander() -> f64 {
    1e-7
}

fn default_initial_frequency_uncertainty() -> f64 {
    100e-6
}

fn default_max_peer_uncertainty() -> f64 {
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
    2.0
}

fn default_steer_frequency_leftover() -> f64 {
    1.0
}

fn default_jump_threshold() -> f64 {
    0.010
}

fn default_slew_max_frequency_offset() -> f64 {
    200e-6
}

fn default_slew_min_duration() -> f64 {
    1.0
}
