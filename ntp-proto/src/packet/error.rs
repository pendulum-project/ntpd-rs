use std::fmt::Display;

use super::NtpPacket;

#[derive(Debug)]
pub enum ParsingError<T> {
    InvalidVersion(u8),
    IncorrectLength,
    MalformedNtsExtensionFields,
    MalformedNonce,
    DecryptError(T),
}

impl<T> ParsingError<T> {
    pub(super) fn get_decrypt_error<U>(self) -> Result<T, ParsingError<U>> {
        match self {
            ParsingError::InvalidVersion(v) => Err(ParsingError::InvalidVersion(v)),
            ParsingError::IncorrectLength => Err(ParsingError::IncorrectLength),
            ParsingError::MalformedNtsExtensionFields => {
                Err(ParsingError::MalformedNtsExtensionFields)
            }
            ParsingError::MalformedNonce => Err(ParsingError::MalformedNonce),
            ParsingError::DecryptError(decrypt_error) => Ok(decrypt_error),
        }
    }
}

impl ParsingError<std::convert::Infallible> {
    pub(super) fn generalize<U>(self) -> ParsingError<U> {
        match self {
            ParsingError::InvalidVersion(v) => ParsingError::InvalidVersion(v),
            ParsingError::IncorrectLength => ParsingError::IncorrectLength,
            ParsingError::MalformedNtsExtensionFields => ParsingError::MalformedNtsExtensionFields,
            ParsingError::MalformedNonce => ParsingError::MalformedNonce,
            ParsingError::DecryptError(decrypt_error) => match decrypt_error {},
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
