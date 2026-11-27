use serde::{
    Deserialize, Serialize,
    de::{self, Visitor},
};
use statime_base::PollInterval;

use crate::{ConfigurableAtomic, IsNonNegative, IsPositive, Positive};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Unit {
    Nanosecond,
    Microsecond,
    Millisecond,
    Second,
    Minute,
    Hour,
    Day,
    Week,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ConfigurableDuration {
    pub unit: Unit,
    pub duration: f64,
}

impl IsPositive for ConfigurableDuration {
    fn is_positive(&self) -> bool {
        self.duration > 0.0
    }
}

impl IsNonNegative for ConfigurableDuration {
    fn is_non_negative(&self) -> bool {
        self.duration >= 0.0
    }
}

impl Serialize for ConfigurableDuration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!(
            "{}{}",
            self.duration,
            match self.unit {
                Unit::Nanosecond => "ns",
                Unit::Microsecond => "us",
                Unit::Millisecond => "ms",
                Unit::Second => "s",
                Unit::Minute => "m",
                Unit::Hour => "h",
                Unit::Day => "d",
                Unit::Week => "w",
            }
        ))
    }
}

fn check_float<E: de::Error>(value: f64) -> Result<f64, E> {
    if value.is_nan() || value.is_infinite() {
        Err(de::Error::custom(
            "Invalid duration, cannot be infinite or a nan",
        ))
    } else {
        Ok(value)
    }
}

struct ConfigurableDurationVisitor;

impl<'de> Visitor<'de> for ConfigurableDurationVisitor {
    type Value = ConfigurableDuration;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("Duration")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if let Some(duration) = v.strip_suffix("ns") {
            Ok(ConfigurableDuration {
                unit: Unit::Nanosecond,
                duration: duration
                    .parse()
                    .map_err(de::Error::custom)
                    .and_then(check_float)?,
            })
        } else if let Some(duration) = v.strip_suffix("us") {
            Ok(ConfigurableDuration {
                unit: Unit::Microsecond,
                duration: duration
                    .parse()
                    .map_err(de::Error::custom)
                    .and_then(check_float)?,
            })
        } else if let Some(duration) = v.strip_suffix("ms") {
            Ok(ConfigurableDuration {
                unit: Unit::Millisecond,
                duration: duration
                    .parse()
                    .map_err(de::Error::custom)
                    .and_then(check_float)?,
            })
        } else if let Some(duration) = v.strip_suffix("s") {
            Ok(ConfigurableDuration {
                unit: Unit::Second,
                duration: duration
                    .parse()
                    .map_err(de::Error::custom)
                    .and_then(check_float)?,
            })
        } else if let Some(duration) = v.strip_suffix("m") {
            Ok(ConfigurableDuration {
                unit: Unit::Minute,
                duration: duration
                    .parse()
                    .map_err(de::Error::custom)
                    .and_then(check_float)?,
            })
        } else if let Some(duration) = v.strip_suffix("h") {
            Ok(ConfigurableDuration {
                unit: Unit::Hour,
                duration: duration
                    .parse()
                    .map_err(de::Error::custom)
                    .and_then(check_float)?,
            })
        } else if let Some(duration) = v.strip_suffix("d") {
            Ok(ConfigurableDuration {
                unit: Unit::Day,
                duration: duration
                    .parse()
                    .map_err(de::Error::custom)
                    .and_then(check_float)?,
            })
        } else if let Some(duration) = v.strip_suffix("w") {
            Ok(ConfigurableDuration {
                unit: Unit::Week,
                duration: duration
                    .parse()
                    .map_err(de::Error::custom)
                    .and_then(check_float)?,
            })
        } else {
            Err(de::Error::custom(format!("Invalid duration {v}")))
        }
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(v)
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(&v)
    }
}

impl<'de> Deserialize<'de> for ConfigurableDuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_str(ConfigurableDurationVisitor)
    }
}

impl ConfigurableAtomic for ConfigurableDuration {}

impl ConfigurableDuration {
    pub fn seconds(self) -> f64 {
        match self.unit {
            Unit::Nanosecond => self.duration * 1e-9,
            Unit::Microsecond => self.duration * 1e-6,
            Unit::Millisecond => self.duration * 1e-3,
            Unit::Second => self.duration,
            Unit::Minute => self.duration * 60.0,
            Unit::Hour => self.duration * (60.0 * 60.0),
            Unit::Day => self.duration * (24.0 * 60.0 * 60.0),
            Unit::Week => self.duration * (7.0 * 24.0 * 60.0 * 60.0),
        }
    }
}

impl From<ConfigurableDuration> for statime_base::Duration {
    fn from(value: ConfigurableDuration) -> Self {
        statime_base::Duration::from_f64_seconds(value.seconds())
    }
}

impl From<Positive<ConfigurableDuration>> for std::time::Duration {
    fn from(value: Positive<ConfigurableDuration>) -> Self {
        std::time::Duration::from_secs_f64(value.into_inner().seconds())
    }
}

impl Positive<ConfigurableDuration> {
    pub fn into_larger_poll_interval(self) -> PollInterval {
        let v = (self.into_inner().seconds().log2() - 1.01f64.log2()).ceil() as i8;
        PollInterval::from_log(v)
    }

    pub fn into_smaller_poll_interval(self) -> PollInterval {
        let v = (self.into_inner().seconds().log2() + 1.01f64.log2()).floor() as i8;
        PollInterval::from_log(v)
    }
}
