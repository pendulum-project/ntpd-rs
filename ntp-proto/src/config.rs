use std::fmt;

use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer,
};

use crate::{
    time_types::{FrequencyTolerance, PollIntervalLimits},
    NtpDuration, PollInterval,
};

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

#[derive(Debug, Default, Copy, Clone)]
pub struct StepThreshold {
    pub forward: Option<NtpDuration>,
    pub backward: Option<NtpDuration>,
}

// We have a custom deserializer for StepThreshold because we
// want to deserialize it from either a number or map
impl<'de> Deserialize<'de> for StepThreshold {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StepThresholdVisitor;

        impl<'de> Visitor<'de> for StepThresholdVisitor {
            type Value = StepThreshold;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("float or map")
            }

            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let duration = NtpDuration::from_seconds(v);
                if duration == NtpDuration::ZERO {
                    Ok(StepThreshold {
                        forward: None,
                        backward: None,
                    })
                } else {
                    Ok(StepThreshold {
                        forward: Some(duration),
                        backward: Some(duration),
                    })
                }
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_f64(v as f64)
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_f64(v as f64)
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<StepThreshold, M::Error> {
                let mut forward = None;
                let mut backward = None;

                while let Some(key) = map.next_key::<&str>()? {
                    match key {
                        "forward" => {
                            if forward.is_some() {
                                return Err(de::Error::duplicate_field("forward"));
                            }
                            let raw: NtpDuration = map.next_value()?;

                            if NtpDuration::ZERO == raw {
                                forward = Some(None)
                            } else {
                                forward = Some(Some(raw))
                            }
                        }
                        "backward" => {
                            if backward.is_some() {
                                return Err(de::Error::duplicate_field("backward"));
                            }
                            let raw: NtpDuration = map.next_value()?;

                            if NtpDuration::ZERO == raw {
                                backward = Some(None)
                            } else {
                                backward = Some(Some(raw))
                            }
                        }
                        _ => {
                            return Err(de::Error::unknown_field(key, &["addr", "mode"]));
                        }
                    }
                }

                Ok(StepThreshold {
                    forward: forward.flatten(),
                    backward: backward.flatten(),
                })
            }
        }

        deserializer.deserialize_any(StepThresholdVisitor)
    }
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
    #[serde(default = "default_panic_threshold")]
    pub panic_threshold: StepThreshold,

    /// The maximum amount the system clock is allowed to change during startup.
    /// This can be used to limit the impact of bad servers if the system clock
    /// is known to be reasonable on startup
    #[serde(default = "startup_panic_threshold")]
    pub startup_panic_threshold: StepThreshold,

    /// The maximum amount distributed amongst all steps except at startup the
    /// daemon is allowed to step the system clock.
    #[serde(deserialize_with = "deserialize_option_threshold", default)]
    pub accumulated_threshold: Option<NtpDuration>,

    /// Stratum of the local clock, when not synchronized through ntp. This
    /// can be used in servers to indicate that there are external mechanisms
    /// synchronizing the clock
    #[serde(default = "default_local_stratum")]
    pub local_stratum: u8,

    /// Minima and maxima for the poll interval of clients
    #[serde(default)]
    pub poll_limits: PollIntervalLimits,

    /// Initial poll interval of the system
    #[serde(default = "default_initial_poll")]
    pub initial_poll: PollInterval,
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            min_intersection_survivors: default_min_intersection_survivors(),
            min_cluster_survivors: default_min_cluster_survivors(),
            frequency_tolerance: default_frequency_tolerance(),
            distance_threshold: default_distance_threshold(),

            frequency_measurement_period: default_frequency_measurement_period(),
            spike_threshold: default_spike_threshold(),
            panic_threshold: default_panic_threshold(),
            startup_panic_threshold: StepThreshold::default(),
            accumulated_threshold: None,

            local_stratum: default_local_stratum(),

            poll_limits: Default::default(),
            initial_poll: default_initial_poll(),
        }
    }
}

fn default_min_intersection_survivors() -> usize {
    3
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

fn default_panic_threshold() -> StepThreshold {
    let raw = NtpDuration::from_seconds(1000.);
    StepThreshold {
        forward: Some(raw),
        backward: Some(raw),
    }
}

fn startup_panic_threshold() -> StepThreshold {
    StepThreshold {
        forward: None,
        backward: Some(NtpDuration::from_seconds(1800.)),
    }
}

fn default_local_stratum() -> u8 {
    16
}

fn default_initial_poll() -> PollInterval {
    PollIntervalLimits::default().min
}
