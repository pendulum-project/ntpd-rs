use std::fmt::Display;

use super::NtpPacket;

#[derive(Debug)]
pub enum ParsingError<T> {
    InvalidVersion(u8),
    IncorrectLength,
    MalformedNtsExtensionFields,
    MalformedNonce,
    MalformedCookiePlaceholder,
    DecryptError(T),
    #[cfg(feature = "ntpv5")]
    InvalidDraftIdentification,
}

impl<T> ParsingError<T> {
    pub(super) fn get_decrypt_error<U>(self) -> Result<T, ParsingError<U>> {
        use ParsingError::*;

        match self {
            InvalidVersion(v) => Err(InvalidVersion(v)),
            IncorrectLength => Err(IncorrectLength),
            MalformedNtsExtensionFields => Err(MalformedNtsExtensionFields),
            MalformedNonce => Err(MalformedNonce),
            MalformedCookiePlaceholder => Err(MalformedCookiePlaceholder),
            #[cfg(feature = "ntpv5")]
            InvalidDraftIdentification => Err(InvalidDraftIdentification),
            DecryptError(decrypt_error) => Ok(decrypt_error),
        }
    }
}

impl ParsingError<std::convert::Infallible> {
    pub(super) fn generalize<U>(self) -> ParsingError<U> {
        use ParsingError::*;

        match self {
            InvalidVersion(v) => InvalidVersion(v),
            IncorrectLength => IncorrectLength,
            MalformedNtsExtensionFields => MalformedNtsExtensionFields,
            MalformedNonce => MalformedNonce,
            MalformedCookiePlaceholder => MalformedCookiePlaceholder,
            #[cfg(feature = "ntpv5")]
            InvalidDraftIdentification => InvalidDraftIdentification,
            DecryptError(decrypt_error) => match decrypt_error {},
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
            Self::MalformedCookiePlaceholder => f.write_str("Malformed cookie placeholder"),
            #[cfg(feature = "ntpv5")]
            Self::InvalidDraftIdentification => f.write_str("Draft Identification invalid"),
            Self::DecryptError(_) => f.write_str("Failed to decrypt NTS extension fields"),
        }
    }
}

impl<T: std::fmt::Debug> std::error::Error for ParsingError<T> {}
