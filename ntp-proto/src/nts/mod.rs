mod messages;
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

#[cfg(feature = "nts-pool")]
impl AeadAlgorithm {
    #[allow(unused)]
    fn description(self) -> Option<AlgorithmDescription> {
        use crate::packet::{AesSivCmac256, AesSivCmac512};

        match self {
            AeadAlgorithm::AeadAesSivCmac256 => Some(AlgorithmDescription {
                id: self,
                keysize: AesSivCmac256::key_size()
                    .try_into()
                    .expect("Aead algorithm has oversized keys"),
            }),
            AeadAlgorithm::AeadAesSivCmac512 => Some(AlgorithmDescription {
                id: self,
                keysize: AesSivCmac512::key_size()
                    .try_into()
                    .expect("Aead algorithm has oversized keys"),
            }),
            AeadAlgorithm::Unknown(_) => None,
        }
    }
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

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCode::UnrecognizedCriticalRecord => f.write_str("Unrecognized critical record"),
            ErrorCode::BadRequest => f.write_str("Bad request"),
            ErrorCode::InternalServerError => f.write_str("Internal server error"),
            ErrorCode::Unknown(id) => write!(f, "Unknown({})", id),
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

/// Error generated during the parsing of NTS messages.
#[derive(Debug)]
pub enum NtsError {
    IO(std::io::Error),
    UnrecognizedCriticalRecord,
    Invalid,
    NoOverlappingProtocol,
    NoOverlappingAlgorithm,
    UnknownWarning(u16),
    Error(ErrorCode),
    #[cfg(feature = "nts-pool")]
    AeadNotSupported(u16),
    #[cfg(feature = "nts-pool")]
    IncorrectSizedKey,
}

impl From<std::io::Error> for NtsError {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value)
    }
}

impl std::fmt::Display for NtsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NtsError::IO(error) => error.fmt(f),
            NtsError::UnrecognizedCriticalRecord => f.write_str("Unrecognized critical record"),
            NtsError::Invalid => f.write_str("Invalid request or response"),
            NtsError::NoOverlappingProtocol => f.write_str("No overlap in supported protocols"),
            NtsError::NoOverlappingAlgorithm => {
                f.write_str("No overlap in supported AEAD algorithms")
            }
            NtsError::UnknownWarning(code) => {
                write!(f, "Received unknown warning from remote: {}", code)
            }
            NtsError::Error(error) => write!(f, "Received error from remote: {}", error),
            #[cfg(feature = "nts-pool")]
            NtsError::AeadNotSupported(v) => {
                write!(f, "Received fixed key request using unknown AEAD({})", v)
            }
            #[cfg(feature = "nts-pool")]
            NtsError::IncorrectSizedKey => {
                write!(f, "Received fix key request with incorrectly sized key(s)")
            }
        }
    }
}

impl std::error::Error for NtsError {}

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
