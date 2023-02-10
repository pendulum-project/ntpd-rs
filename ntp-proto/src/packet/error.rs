use std::fmt::Display;

use crate::NtpPacket;

#[derive(Debug)]
pub enum ParsingError<T> {
    InvalidVersion(u8),
    IncorrectLength,
    MalformedNtsExtensionFields,
    MalformedNonce,
    DecryptError(T),
}

impl<T> ParsingError<T> {
    pub(super) fn coerce<U>(self) -> Option<ParsingError<U>> {
        match self {
            ParsingError::InvalidVersion(v) => Some(ParsingError::InvalidVersion(v)),
            ParsingError::IncorrectLength => Some(ParsingError::IncorrectLength),
            ParsingError::MalformedNtsExtensionFields => {
                Some(ParsingError::MalformedNtsExtensionFields)
            }
            ParsingError::MalformedNonce => Some(ParsingError::MalformedNonce),
            ParsingError::DecryptError(_) => None,
        }
    }
}

impl ParsingError<std::convert::Infallible> {
    pub(super) fn force<U>(self) -> ParsingError<U> {
        match self {
            ParsingError::InvalidVersion(v) => ParsingError::InvalidVersion(v),
            ParsingError::IncorrectLength => ParsingError::IncorrectLength,
            ParsingError::MalformedNtsExtensionFields => ParsingError::MalformedNtsExtensionFields,
            ParsingError::MalformedNonce => ParsingError::MalformedNonce,
            ParsingError::DecryptError(_) => unreachable!(),
        }
    }
}

pub type PacketParsingError<'a> = ParsingError<NtpPacket<'a>>;

impl<T> Display for ParsingError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidVersion(version) => f.write_fmt(format_args!("Invalid version {version}")),
            Self::IncorrectLength => f.write_str("Incorrect packet length"),
            Self::MalformedNtsExtensionFields => f.write_str("Malformed nts extension fields"),
            Self::MalformedNonce => f.write_str("Malformed nonce (likely invalid length)"),
            Self::DecryptError(_) => f.write_str("Failed to decrypt NTS extension fields"),
        }
    }
}

impl<T: std::fmt::Debug> std::error::Error for ParsingError<T> {}
