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
    V5(super::v5::V5Error),
}

impl<T> ParsingError<T> {
    pub(super) fn get_decrypt_error<U>(self) -> Result<T, ParsingError<U>> {
        #[cfg(feature = "ntpv5")]
        use ParsingError::V5;
        use ParsingError::{
            DecryptError, IncorrectLength, InvalidVersion, MalformedCookiePlaceholder,
            MalformedNonce, MalformedNtsExtensionFields,
        };

        match self {
            InvalidVersion(v) => Err(InvalidVersion(v)),
            IncorrectLength => Err(IncorrectLength),
            MalformedNtsExtensionFields => Err(MalformedNtsExtensionFields),
            MalformedNonce => Err(MalformedNonce),
            MalformedCookiePlaceholder => Err(MalformedCookiePlaceholder),
            DecryptError(decrypt_error) => Ok(decrypt_error),
            #[cfg(feature = "ntpv5")]
            V5(e) => Err(V5(e)),
        }
    }
}

impl ParsingError<std::convert::Infallible> {
    pub(super) fn generalize<U>(self) -> ParsingError<U> {
        use ParsingError::{
            DecryptError, IncorrectLength, InvalidVersion, MalformedCookiePlaceholder,
            MalformedNonce, MalformedNtsExtensionFields,
        };
        #[cfg(feature = "ntpv5")]
        use ParsingError::V5;

        match self {
            InvalidVersion(v) => InvalidVersion(v),
            IncorrectLength => IncorrectLength,
            MalformedNtsExtensionFields => MalformedNtsExtensionFields,
            MalformedNonce => MalformedNonce,
            MalformedCookiePlaceholder => MalformedCookiePlaceholder,
            DecryptError(decrypt_error) => match decrypt_error {},
            #[cfg(feature = "ntpv5")]
            V5(e) => V5(e),
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
            Self::DecryptError(_) => f.write_str("Failed to decrypt NTS extension fields"),
            #[cfg(feature = "ntpv5")]
            Self::V5(e) => Display::fmt(e, f),
        }
    }
}

impl<T: std::fmt::Debug> std::error::Error for ParsingError<T> {}
