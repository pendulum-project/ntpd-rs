mod record;

/// From https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
enum AeadAlgorithm {
    AeadAesSivCmac256,
    AeadAesSivCmac512,
    Unknown(u16),
}

impl From<u16> for AeadAlgorithm {
    fn from(value: u16) -> Self {
        match value {
            15 => Self::AeadAesSivCmac256,
            17 => Self::AeadAesSivCmac512,
            v => Self::Unknown(v),
        }
    }
}

impl From<AeadAlgorithm> for u16 {
    fn from(value: AeadAlgorithm) -> Self {
        match value {
            AeadAlgorithm::AeadAesSivCmac256 => 15,
            AeadAlgorithm::AeadAesSivCmac512 => 17,
            AeadAlgorithm::Unknown(v) => v,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
enum NextProtocol {
    NTPv4,
    DraftNTPv5,
    Unknown(u16),
}

impl From<u16> for NextProtocol {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::NTPv4,
            0x8001 => Self::DraftNTPv5,
            v => Self::Unknown(v),
        }
    }
}

impl From<NextProtocol> for u16 {
    fn from(value: NextProtocol) -> Self {
        match value {
            NextProtocol::NTPv4 => 0,
            NextProtocol::DraftNTPv5 => 0x8001,
            NextProtocol::Unknown(v) => v,
        }
    }
}

#[cfg(feature = "nts-pool")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AlgorithmDescription {
    id: AeadAlgorithm,
    keysize: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    UnrecognizedCriticalRecord,
    BadRequest,
    InternalServerError,
    Unknown(u16),
}

impl From<u16> for ErrorCode {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::UnrecognizedCriticalRecord,
            1 => Self::BadRequest,
            2 => Self::InternalServerError,
            v => Self::Unknown(v),
        }
    }
}

impl From<ErrorCode> for u16 {
    fn from(value: ErrorCode) -> Self {
        match value {
            ErrorCode::UnrecognizedCriticalRecord => 0,
            ErrorCode::BadRequest => 1,
            ErrorCode::InternalServerError => 2,
            ErrorCode::Unknown(v) => v,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WarningCode {
    Unknown(u16),
}

impl From<u16> for WarningCode {
    fn from(value: u16) -> Self {
        Self::Unknown(value)
    }
}

impl From<WarningCode> for u16 {
    fn from(value: WarningCode) -> Self {
        match value {
            WarningCode::Unknown(v) => v,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_algorithm_encoding() {
        for i in 0..=u16::MAX {
            assert_eq!(i, u16::from(AeadAlgorithm::from(i)));
        }
    }

    #[test]
    fn test_next_protocol_encoding() {
        for i in 0..=u16::MAX {
            assert_eq!(i, u16::from(NextProtocol::from(i)));
        }
    }

    #[test]
    fn test_error_code_encoding() {
        for i in 0..=u16::MAX {
            assert_eq!(i, u16::from(ErrorCode::from(i)));
        }
    }

    #[test]
    fn test_warning_code_encoding() {
        for i in 0..=u16::MAX {
            assert_eq!(i, u16::from(WarningCode::from(i)));
        }
    }
}
