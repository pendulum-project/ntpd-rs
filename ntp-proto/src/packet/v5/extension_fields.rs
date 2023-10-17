#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Type {
    DraftIdentification,
    Padding,
    Mac,
    ReferenceIdRequest,
    ReferenceIdResponse,
    ServerInformation,
    Correction,
    ReferenceTimestamp,
    MonotonicReceiveTimestamp,
    SecondaryReceiveTimestamp,
    Unknown(u16),
}

impl Type {
    pub fn from_bits(bits: u16) -> Self {
        match bits {
            0xF5FF => Self::DraftIdentification,
            0xF501 => Self::Padding,
            0xF502 => Self::Mac,
            0xF503 => Self::ReferenceIdRequest,
            0xF504 => Self::ReferenceIdResponse,
            0xF505 => Self::ServerInformation,
            0xF506 => Self::Correction,
            0xF507 => Self::ReferenceTimestamp,
            0xF508 => Self::MonotonicReceiveTimestamp,
            0xF509 => Self::SecondaryReceiveTimestamp,
            other => Self::Unknown(other),
        }
    }

    pub fn to_bits(self) -> u16 {
        match self {
            Self::DraftIdentification => 0xF5FF,
            Self::Padding => 0xF501,
            Self::Mac => 0xF502,
            Self::ReferenceIdRequest => 0xF503,
            Self::ReferenceIdResponse => 0xF504,
            Self::ServerInformation => 0xF505,
            Self::Correction => 0xF506,
            Self::ReferenceTimestamp => 0xF507,
            Self::MonotonicReceiveTimestamp => 0xF508,
            Self::SecondaryReceiveTimestamp => 0xF509,
            Self::Unknown(other) => other,
        }
    }

    #[cfg(test)]
    fn all_known() -> impl Iterator<Item = Self> {
        [
            Self::DraftIdentification,
            Self::Padding,
            Self::Mac,
            Self::ReferenceIdRequest,
            Self::ReferenceIdResponse,
            Self::ServerInformation,
            Self::Correction,
            Self::ReferenceTimestamp,
            Self::MonotonicReceiveTimestamp,
            Self::SecondaryReceiveTimestamp,
        ]
        .iter()
        .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_round_trip() {
        for i in 0..=u16::MAX {
            let ty = Type::from_bits(i);
            assert_eq!(i, ty.to_bits());
        }

        for ty in Type::all_known() {
            let bits = ty.to_bits();
            let ty2 = Type::from_bits(bits);
            assert_eq!(ty, ty2);

            let bits2 = ty2.to_bits();
            assert_eq!(bits, bits2);
        }
    }
}
