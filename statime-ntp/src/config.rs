use std::fmt;

use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Unexpected, Visitor},
};

use crate::time_types::{NtpDuration, PollInterval, PollIntervalLimits};

#[derive(Debug, Default, Copy, Clone)]
pub struct ReferenceIdConfig {
    id: u32,
}

impl ReferenceIdConfig {
    pub(crate) fn to_reference_id(self) -> crate::ReferenceId {
        crate::ReferenceId::from_int(self.id)
    }
}

// Deserialize from the string type in config
impl<'de> Deserialize<'de> for ReferenceIdConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ReferenceIdConfigVisitor;

        impl Visitor<'_> for ReferenceIdConfigVisitor {
            type Value = ReferenceIdConfig;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("up to 4-character string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let mut chars: Vec<char> = v.chars().collect();
                if chars.len() > 4 {
                    return Err(E::invalid_length(chars.len(), &self));
                }

                // Pad with spaces
                while chars.len() < 4 {
                    chars.push(' ');
                }

                let encoded = chars.iter().fold(0u32, |acc, &c| (acc << 8) | (c as u32));

                Ok(ReferenceIdConfig { id: encoded })
            }
        }

        deserializer.deserialize_str(ReferenceIdConfigVisitor)
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct StepThreshold {
    pub forward: Option<NtpDuration>,
    pub backward: Option<NtpDuration>,
}

impl StepThreshold {
    pub fn is_within(&self, duration: NtpDuration) -> bool {
        self.forward.is_none_or(|v| duration < v) && self.backward.is_none_or(|v| duration > -v)
    }
}

#[derive(Debug, Copy, Clone)]
struct ThresholdPart(Option<NtpDuration>);

impl<'de> Deserialize<'de> for ThresholdPart {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ThresholdPartVisitor;

        impl Visitor<'_> for ThresholdPartVisitor {
            type Value = ThresholdPart;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("float or \"inf\"")
            }

            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(ThresholdPart(Some(NtpDuration::from_seconds(v))))
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

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v != "inf" {
                    return Err(de::Error::invalid_value(
                        de::Unexpected::Str(v),
                        &"float or \"inf\"",
                    ));
                }
                Ok(ThresholdPart(None))
            }
        }

        deserializer.deserialize_any(ThresholdPartVisitor)
    }
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
                formatter.write_str("float, map or \"inf\"")
            }

            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.is_nan() || v.is_infinite() || v < 0.0 {
                    return Err(serde::de::Error::invalid_value(
                        Unexpected::Float(v),
                        &"a positive number",
                    ));
                }

                let duration = NtpDuration::from_seconds(v);

                Ok(StepThreshold {
                    forward: Some(duration),
                    backward: Some(duration),
                })
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

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v != "inf" {
                    return Err(de::Error::invalid_value(
                        de::Unexpected::Str(v),
                        &"float, map or \"inf\"",
                    ));
                }
                Ok(StepThreshold {
                    forward: None,
                    backward: None,
                })
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<StepThreshold, M::Error> {
                let mut forward = None;
                let mut backward = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "forward" => {
                            if forward.is_some() {
                                return Err(de::Error::duplicate_field("forward"));
                            }
                            let raw: ThresholdPart = map.next_value()?;
                            forward = Some(raw.0);
                        }
                        "backward" => {
                            if backward.is_some() {
                                return Err(de::Error::duplicate_field("backward"));
                            }
                            let raw: ThresholdPart = map.next_value()?;
                            backward = Some(raw.0);
                        }
                        _ => {
                            return Err(de::Error::unknown_field(
                                key.as_str(),
                                &["forward", "backward"],
                            ));
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
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SourceConfig {
    /// Minima and maxima for the poll interval of clients
    #[serde(default)]
    pub poll_interval_limits: PollIntervalLimits,

    /// Initial poll interval of the system
    #[serde(default = "default_initial_poll_interval")]
    pub initial_poll_interval: PollInterval,
}

impl Default for SourceConfig {
    fn default() -> Self {
        Self {
            poll_interval_limits: PollIntervalLimits::default(),
            initial_poll_interval: default_initial_poll_interval(),
        }
    }
}

fn default_initial_poll_interval() -> PollInterval {
    PollIntervalLimits::default().min
}

#[derive(Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NtpConfig {
    /// Stratum of the local clock, when not synchronized through ntp. This
    /// can be used in servers to indicate that there are external mechanisms
    /// synchronizing the clock
    #[serde(default = "default_local_stratum")]
    pub local_stratum: u8,

    /// Reference ID for clock synchronization. When stratum is 1 this value
    /// is used - the value is left justified, limited to four characters
    /// and zero padded.
    ///
    /// From RFC 5905:
    ///
    ///  +------+----------------------------------------------------------+
    ///  | ID   | Clock Source                                             |
    ///  +------+----------------------------------------------------------+
    ///  | GOES | Geosynchronous Orbit Environment Satellite               |
    ///  | GPS  | Global Position System                                   |
    ///  | GAL  | Galileo Positioning System                               |
    ///  | PPS  | Generic pulse-per-second                                 |
    ///  | IRIG | Inter-Range Instrumentation Group                        |
    ///  | WWVB | LF Radio WWVB Ft. Collins, CO 60 kHz                     |
    ///  | DCF  | LF Radio DCF77 Mainflingen, DE 77.5 kHz                  |
    ///  | HBG  | LF Radio HBG Prangins, HB 75 kHz                         |
    ///  | MSF  | LF Radio MSF Anthorn, UK 60 kHz                          |
    ///  | JJY  | LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz       |
    ///  | LORC | MF Radio LORAN C station, 100 kHz                        |
    ///  | TDF  | MF Radio Allouis, FR 162 kHz                             |
    ///  | CHU  | HF Radio CHU Ottawa, Ontario                             |
    ///  | WWV  | HF Radio WWV Ft. Collins, CO                             |
    ///  | WWVH | HF Radio WWVH Kauai, HI                                  |
    ///  | NIST | NIST telephone modem                                     |
    ///  | ACTS | NIST telephone modem                                     |
    ///  | USNO | USNO telephone modem                                     |
    ///  | PTB  | European telephone modem                                 |
    ///  +------+----------------------------------------------------------+
    ///
    /// Any string beginning with the ASCII character "X" is can be used for
    /// experimentation and development.
    ///
    /// The default value is "XNON" (i.e. NONE)
    ///
    /// When the local-stratum not 1 the reference-id is ignored.
    ///
    #[serde(default = "default_reference_id")]
    pub reference_id: ReferenceIdConfig,
}

impl Default for NtpConfig {
    fn default() -> Self {
        Self {
            local_stratum: default_local_stratum(),
            reference_id: default_reference_id(),
        }
    }
}

fn default_reference_id() -> ReferenceIdConfig {
    ReferenceIdConfig {
        id: ['X', 'N', 'O', 'N']
            .iter()
            .fold(0u32, |acc, &c| (acc << 8) | (c as u32)),
    }
}

fn default_local_stratum() -> u8 {
    16
}
