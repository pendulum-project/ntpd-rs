use std::{marker::PhantomData, net::SocketAddr};

use ntp_proto::PollInterval;
use serde::{
    Deserialize, Serialize,
    de::{self, Visitor},
};
use statime_base::Duration;
use statime_config::{ConfigurableAtomic, IsPositive, Positive};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) enum Unit {
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
pub(crate) struct ConfigurableDuration {
    pub(super) unit: Unit,
    pub(super) duration: f64,
}

impl IsPositive for ConfigurableDuration {
    fn is_positive(&self) -> bool {
        self.duration > 0.0
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
    fn seconds(self) -> f64 {
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

impl ConfigurableDuration {
    pub(crate) fn into_std_duration(value: Positive<ConfigurableDuration>) -> std::time::Duration {
        std::time::Duration::from_secs_f64(value.into_inner().seconds())
    }

    pub(crate) fn into_larger_poll_interval(this: Positive<ConfigurableDuration>) -> PollInterval {
        let v = (this.into_inner().seconds().log2() - 0.01f64.log2()).ceil() as i8;
        PollInterval::from_byte(v.cast_unsigned())
    }

    pub(crate) fn into_smaller_poll_interval(this: Positive<ConfigurableDuration>) -> PollInterval {
        let v = (this.into_inner().seconds().log2() + 0.01f64.log2()).floor() as i8;
        PollInterval::from_byte(v.cast_unsigned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ConfigurableAtomic)]
pub(crate) struct NetworkAddress {
    pub(crate) server: String,
    pub(crate) port: Option<u16>,
}

impl Serialize for NetworkAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.port {
            Some(port) if self.server.contains(':') => {
                serializer.serialize_str(&format!("[{}]:{}", self.server, port))
            }
            Some(port) => serializer.serialize_str(&format!("{}:{}", self.server, port)),
            None => serializer.serialize_str(&self.server),
        }
    }
}

impl<'de> Deserialize<'de> for NetworkAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let raw_address = String::deserialize(deserializer)?;

        if raw_address.split(':').count() > 2 {
            // Ipv6, parse it
            match raw_address.parse::<SocketAddr>() {
                Ok(socket_addr) => Ok(NetworkAddress {
                    server: socket_addr.ip().to_string(),
                    port: Some(socket_addr.port()),
                }),
                Err(e) => {
                    // Could be because of no port, add one and see
                    let address_with_port = format!("[{raw_address}]:1");
                    if let Ok(socket_addr) = address_with_port.parse::<SocketAddr>() {
                        Ok(NetworkAddress {
                            server: socket_addr.ip().to_string(),
                            port: None,
                        })
                    } else {
                        Err(serde::de::Error::custom(e))
                    }
                }
            }
        } else if let Some((server_name, port)) = raw_address.split_once(':') {
            Ok(NetworkAddress {
                server: server_name.into(),
                port: Some(port.parse().map_err(serde::de::Error::custom)?),
            })
        } else {
            Ok(NetworkAddress {
                server: raw_address,
                port: None,
            })
        }
    }
}
