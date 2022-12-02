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
