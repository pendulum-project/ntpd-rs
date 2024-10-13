#![allow(clippy::cast_possible_truncation)]
use std::{
    borrow::Cow,
    io::{Cursor, Write},
};

use crate::{io::NonBlockingWrite, keyset::DecodedServerCookie};

#[cfg(feature = "ntpv5")]
use crate::packet::v5::extension_fields::{ReferenceIdRequest, ReferenceIdResponse};

use super::{crypto::EncryptResult, error::ParsingError, Cipher, CipherProvider, Mac};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ExtensionFieldTypeId {
    UniqueIdentifier,
    NtsCookie,
    NtsCookiePlaceholder,
    NtsEncryptedField,
    Unknown {
        type_id: u16,
    },
    #[cfg(feature = "ntpv5")]
    DraftIdentification,
    #[cfg(feature = "ntpv5")]
    Padding,
    #[cfg(feature = "ntpv5")]
    ReferenceIdRequest,
    #[cfg(feature = "ntpv5")]
    ReferenceIdResponse,
}

impl ExtensionFieldTypeId {
    fn from_type_id(type_id: u16) -> Self {
        match type_id {
            0x104 => Self::UniqueIdentifier,
            0x204 => Self::NtsCookie,
            0x304 => Self::NtsCookiePlaceholder,
            0x404 => Self::NtsEncryptedField,
            #[cfg(feature = "ntpv5")]
            0xF5FF => Self::DraftIdentification,
            #[cfg(feature = "ntpv5")]
            0xF501 => Self::Padding,
            #[cfg(feature = "ntpv5")]
            0xF503 => Self::ReferenceIdRequest,
            #[cfg(feature = "ntpv5")]
            0xF504 => Self::ReferenceIdResponse,
            _ => Self::Unknown { type_id },
        }
    }

    fn to_type_id(self) -> u16 {
        match self {
            ExtensionFieldTypeId::UniqueIdentifier => 0x104,
            ExtensionFieldTypeId::NtsCookie => 0x204,
            ExtensionFieldTypeId::NtsCookiePlaceholder => 0x304,
            ExtensionFieldTypeId::NtsEncryptedField => 0x404,
            #[cfg(feature = "ntpv5")]
            ExtensionFieldTypeId::DraftIdentification => 0xF5FF,
            #[cfg(feature = "ntpv5")]
            ExtensionFieldTypeId::Padding => 0xF501,
            #[cfg(feature = "ntpv5")]
            ExtensionFieldTypeId::ReferenceIdRequest => 0xF503,
            #[cfg(feature = "ntpv5")]
            ExtensionFieldTypeId::ReferenceIdResponse => 0xF504,
            ExtensionFieldTypeId::Unknown { type_id } => type_id,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ExtensionField<'a> {
    UniqueIdentifier(Cow<'a, [u8]>),
    NtsCookie(Cow<'a, [u8]>),
    NtsCookiePlaceholder {
        cookie_length: u16,
    },
    InvalidNtsEncryptedField,
    #[cfg(feature = "ntpv5")]
    DraftIdentification(Cow<'a, str>),
    #[cfg(feature = "ntpv5")]
    Padding(usize),
    #[cfg(feature = "ntpv5")]
    ReferenceIdRequest(super::v5::extension_fields::ReferenceIdRequest),
    #[cfg(feature = "ntpv5")]
    ReferenceIdResponse(super::v5::extension_fields::ReferenceIdResponse<'a>),
    Unknown {
        type_id: u16,
        data: Cow<'a, [u8]>,
    },
}

impl<'a> std::fmt::Debug for ExtensionField<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UniqueIdentifier(arg0) => f.debug_tuple("UniqueIdentifier").field(arg0).finish(),
            Self::NtsCookie(arg0) => f.debug_tuple("NtsCookie").field(arg0).finish(),
            Self::NtsCookiePlaceholder {
                cookie_length: body_length,
            } => f
                .debug_struct("NtsCookiePlaceholder")
                .field("body_length", body_length)
                .finish(),
            Self::InvalidNtsEncryptedField => f.debug_struct("InvalidNtsEncryptedField").finish(),
            #[cfg(feature = "ntpv5")]
            Self::DraftIdentification(arg0) => {
                f.debug_tuple("DraftIdentification").field(arg0).finish()
            }
            #[cfg(feature = "ntpv5")]
            Self::Padding(len) => f.debug_struct("Padding").field("length", &len).finish(),
            #[cfg(feature = "ntpv5")]
            Self::ReferenceIdRequest(r) => f.debug_tuple("ReferenceIdRequest").field(r).finish(),
            #[cfg(feature = "ntpv5")]
            Self::ReferenceIdResponse(r) => f.debug_tuple("ReferenceIdResponse").field(r).finish(),
            Self::Unknown {
                type_id: typeid,
                data,
            } => f
                .debug_struct("Unknown")
                .field("typeid", typeid)
                .field("length", &data.len())
                .field("data", data)
                .finish(),
        }
    }
}

impl<'a> ExtensionField<'a> {
    const HEADER_LENGTH: usize = 4;

    #[must_use] pub fn into_owned(self) -> ExtensionField<'static> {
        use ExtensionField::{DraftIdentification, InvalidNtsEncryptedField, NtsCookie, NtsCookiePlaceholder, Padding, ReferenceIdRequest, ReferenceIdResponse, UniqueIdentifier, Unknown};

        match self {
            Unknown {
                type_id: typeid,
                data,
            } => Unknown {
                type_id: typeid,
                data: Cow::Owned(data.into_owned()),
            },
            UniqueIdentifier(data) => UniqueIdentifier(Cow::Owned(data.into_owned())),
            NtsCookie(data) => NtsCookie(Cow::Owned(data.into_owned())),
            NtsCookiePlaceholder {
                cookie_length: body_length,
            } => NtsCookiePlaceholder {
                cookie_length: body_length,
            },
            InvalidNtsEncryptedField => InvalidNtsEncryptedField,
            #[cfg(feature = "ntpv5")]
            DraftIdentification(data) => DraftIdentification(Cow::Owned(data.into_owned())),
            #[cfg(feature = "ntpv5")]
            Padding(len) => Padding(len),
            #[cfg(feature = "ntpv5")]
            ReferenceIdRequest(req) => ReferenceIdRequest(req),
            #[cfg(feature = "ntpv5")]
            ReferenceIdResponse(res) => ReferenceIdResponse(res.into_owned()),
        }
    }

    pub(crate) fn serialize(
        &self,
        w: impl NonBlockingWrite,
        minimum_size: u16,
        version: ExtensionHeaderVersion,
    ) -> std::io::Result<()> {
        use ExtensionField::{DraftIdentification, InvalidNtsEncryptedField, NtsCookie, NtsCookiePlaceholder, Padding, ReferenceIdRequest, ReferenceIdResponse, UniqueIdentifier, Unknown};

        match self {
            Unknown { type_id, data } => {
                Self::encode_unknown(w, *type_id, data, minimum_size, version)
            }
            UniqueIdentifier(identifier) => {
                Self::encode_unique_identifier(w, identifier, minimum_size, version)
            }
            NtsCookie(cookie) => Self::encode_nts_cookie(w, cookie, minimum_size, version),
            NtsCookiePlaceholder {
                cookie_length: body_length,
            } => Self::encode_nts_cookie_placeholder(w, *body_length, minimum_size, version),
            InvalidNtsEncryptedField => Err(std::io::ErrorKind::Other.into()),
            #[cfg(feature = "ntpv5")]
            DraftIdentification(data) => {
                Self::encode_draft_identification(w, data, minimum_size, version)
            }
            #[cfg(feature = "ntpv5")]
            Padding(len) => Self::encode_padding_field(w, *len, minimum_size, version),
            #[cfg(feature = "ntpv5")]
            ReferenceIdRequest(req) => req.serialize(w),
            #[cfg(feature = "ntpv5")]
            ReferenceIdResponse(res) => res.serialize(w),
        }
    }

    #[cfg(feature = "__internal-fuzz")]
    pub fn serialize_pub(
        &self,
        w: impl NonBlockingWrite,
        minimum_size: u16,
        version: ExtensionHeaderVersion,
    ) -> std::io::Result<()> {
        self.serialize(w, minimum_size, version)
    }

    fn encode_framing(
        mut w: impl NonBlockingWrite,
        ef_id: ExtensionFieldTypeId,
        data_length: usize,
        minimum_size: u16,
        version: ExtensionHeaderVersion,
    ) -> std::io::Result<()> {
        if data_length > u16::MAX as usize - ExtensionField::HEADER_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Extension field too long",
            ));
        }

        // u16 for the type_id, u16 for the length
        let mut actual_length =
            (data_length as u16 + ExtensionField::HEADER_LENGTH as u16).max(minimum_size);

        if version == ExtensionHeaderVersion::V4 {
            actual_length = next_multiple_of_u16(actual_length, 4);
        }

        w.write_all(&ef_id.to_type_id().to_be_bytes())?;
        w.write_all(&actual_length.to_be_bytes())
    }

    fn encode_padding(
        w: impl NonBlockingWrite,
        data_length: usize,
        minimum_size: u16,
    ) -> std::io::Result<()> {
        if data_length > u16::MAX as usize - ExtensionField::HEADER_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Extension field too long",
            ));
        }

        let actual_length = next_multiple_of_usize(
            (data_length + ExtensionField::HEADER_LENGTH).max(minimum_size as usize),
            4,
        );

        Self::write_zeros(
            w,
            actual_length - data_length - ExtensionField::HEADER_LENGTH,
        )
    }

    fn write_zeros(mut w: impl NonBlockingWrite, n: usize) -> std::io::Result<()> {
        let mut remaining = n;
        let padding_bytes = [0_u8; 32];
        while remaining > 0 {
            let added = usize::min(remaining, padding_bytes.len());
            w.write_all(&padding_bytes[..added])?;

            remaining -= added;
        }

        Ok(())
    }

    fn encode_unique_identifier(
        mut w: impl NonBlockingWrite,
        identifier: &[u8],
        minimum_size: u16,
        version: ExtensionHeaderVersion,
    ) -> std::io::Result<()> {
        Self::encode_framing(
            &mut w,
            ExtensionFieldTypeId::UniqueIdentifier,
            identifier.len(),
            minimum_size,
            version,
        )?;
        w.write_all(identifier)?;
        Self::encode_padding(w, identifier.len(), minimum_size)
    }

    fn encode_nts_cookie(
        mut w: impl NonBlockingWrite,
        cookie: &[u8],
        minimum_size: u16,
        version: ExtensionHeaderVersion,
    ) -> std::io::Result<()> {
        Self::encode_framing(
            &mut w,
            ExtensionFieldTypeId::NtsCookie,
            cookie.len(),
            minimum_size,
            version,
        )?;

        w.write_all(cookie)?;

        Self::encode_padding(w, cookie.len(), minimum_size)?;

        Ok(())
    }

    fn encode_nts_cookie_placeholder(
        mut w: impl NonBlockingWrite,
        cookie_length: u16,
        minimum_size: u16,
        version: ExtensionHeaderVersion,
    ) -> std::io::Result<()> {
        Self::encode_framing(
            &mut w,
            ExtensionFieldTypeId::NtsCookiePlaceholder,
            cookie_length as usize,
            minimum_size,
            version,
        )?;

        Self::write_zeros(&mut w, cookie_length as usize)?;

        Self::encode_padding(w, cookie_length as usize, minimum_size)?;

        Ok(())
    }

    fn encode_unknown(
        mut w: impl NonBlockingWrite,
        type_id: u16,
        data: &[u8],
        minimum_size: u16,
        version: ExtensionHeaderVersion,
    ) -> std::io::Result<()> {
        Self::encode_framing(
            &mut w,
            ExtensionFieldTypeId::Unknown { type_id },
            data.len(),
            minimum_size,
            version,
        )?;

        w.write_all(data)?;

        Self::encode_padding(w, data.len(), minimum_size)?;

        Ok(())
    }

    fn encode_encrypted(
        w: &mut Cursor<&mut [u8]>,
        fields_to_encrypt: &[ExtensionField],
        cipher: &dyn Cipher,
        version: ExtensionHeaderVersion,
    ) -> std::io::Result<()> {
        let padding = [0; 4];

        let header_start = w.position();

        // Placeholder header
        let type_id: u16 = ExtensionFieldTypeId::NtsEncryptedField.to_type_id();
        w.write_all(&type_id.to_be_bytes())?;
        w.write_all(&0u16.to_be_bytes())?;
        w.write_all(&0u16.to_be_bytes())?;
        w.write_all(&0u16.to_be_bytes())?;

        // Write plaintext for the fields
        let plaintext_start = w.position();
        for field in fields_to_encrypt {
            // RFC 8915, section 5.5: contrary to the RFC 7822 requirement that fields have a minimum length of 16 or 28 octets,
            // encrypted extension fields MAY be arbitrarily short (but still MUST be a multiple of 4 octets in length)
            let minimum_size = 0;
            field.serialize(&mut *w, minimum_size, version)?;
        }

        let plaintext_length = w.position() - plaintext_start;
        let (packet_so_far, cur_extension_field) = w.get_mut().split_at_mut(header_start as usize);
        let header_size = (plaintext_start - header_start) as usize;
        let EncryptResult {
            nonce_length,
            ciphertext_length,
        } = cipher.encrypt(
            &mut cur_extension_field[header_size..],
            plaintext_length as usize,
            packet_so_far,
        )?;

        // Nonce and ciphertext lengths may not be a multiple of 4, so add padding to them
        // to make their lengths multiples of 4.
        let padded_nonce_length = next_multiple_of_usize(nonce_length, 4);
        let padded_ciphertext_length = next_multiple_of_usize(ciphertext_length, 4);
        if cur_extension_field.len()
            < (plaintext_start - header_start) as usize
                + padded_ciphertext_length
                + padded_nonce_length
        {
            return Err(std::io::ErrorKind::WriteZero.into());
        }

        // move the ciphertext over to make space for nonce padding
        cur_extension_field.copy_within(
            header_size + nonce_length..header_size + nonce_length + ciphertext_length,
            header_size + padded_nonce_length,
        );

        // zero out then nonce padding
        let nonce_padding = padded_nonce_length - nonce_length;
        cur_extension_field[header_size + nonce_length..][..nonce_padding]
            .copy_from_slice(&padding[..nonce_padding]);

        // zero out the ciphertext padding
        let ciphertext_padding = padded_ciphertext_length - ciphertext_length;
        debug_assert_eq!(
            ciphertext_padding, 0,
            "extension field encoding should add padding"
        );
        cur_extension_field[header_size + padded_nonce_length + ciphertext_length..]
            [..ciphertext_padding]
            .copy_from_slice(&padding[..ciphertext_padding]);

        // go back and fill in the header
        let signature_length = header_size + padded_nonce_length + padded_ciphertext_length;
        w.set_position(header_start);

        let type_id: u16 = ExtensionFieldTypeId::NtsEncryptedField.to_type_id();
        w.write_all(&type_id.to_be_bytes())?;
        w.write_all(&(signature_length as u16).to_be_bytes())?;
        w.write_all(&(nonce_length as u16).to_be_bytes())?;
        w.write_all(&(ciphertext_length as u16).to_be_bytes())?;

        // set the final position
        w.set_position(header_start + signature_length as u64);

        Ok(())
    }

    #[cfg(feature = "ntpv5")]
    fn encode_draft_identification(
        mut w: impl NonBlockingWrite,
        data: &str,
        minimum_size: u16,
        version: ExtensionHeaderVersion,
    ) -> std::io::Result<()> {
        Self::encode_framing(
            &mut w,
            ExtensionFieldTypeId::DraftIdentification,
            data.len(),
            minimum_size,
            version,
        )?;

        w.write_all(data.as_bytes())?;

        Self::encode_padding(w, data.len(), minimum_size)?;

        Ok(())
    }

    #[cfg(feature = "ntpv5")]
    pub fn encode_padding_field(
        mut w: impl NonBlockingWrite,
        length: usize,
        minimum_size: u16,
        version: ExtensionHeaderVersion,
    ) -> std::io::Result<()> {
        Self::encode_framing(
            &mut w,
            ExtensionFieldTypeId::Padding,
            length - Self::HEADER_LENGTH,
            minimum_size,
            version,
        )?;

        Self::write_zeros(&mut w, length - Self::HEADER_LENGTH)?;
        Self::encode_padding(w, length - Self::HEADER_LENGTH, minimum_size)?;

        Ok(())
    }

    fn decode_unique_identifier(
        message: &'a [u8],
    ) -> Result<Self, ParsingError<std::convert::Infallible>> {
        // The string MUST be at least 32 octets long
        // TODO: Discuss if we really want this check here
        if message.len() < 32 {
            return Err(ParsingError::IncorrectLength);
        }

        Ok(ExtensionField::UniqueIdentifier(message[..].into()))
    }

    fn decode_nts_cookie(
        message: &'a [u8],
    ) -> Result<Self, ParsingError<std::convert::Infallible>> {
        Ok(ExtensionField::NtsCookie(message[..].into()))
    }

    fn decode_nts_cookie_placeholder(
        message: &'a [u8],
    ) -> Result<Self, ParsingError<std::convert::Infallible>> {
        if message.iter().any(|b| *b != 0) {
            Err(ParsingError::MalformedCookiePlaceholder)
        } else {
            Ok(ExtensionField::NtsCookiePlaceholder {
                cookie_length: message.len() as u16,
            })
        }
    }

    fn decode_unknown(
        type_id: u16,
        message: &'a [u8],
    ) -> Result<Self, ParsingError<std::convert::Infallible>> {
        Ok(ExtensionField::Unknown {
            type_id,
            data: Cow::Borrowed(message),
        })
    }

    #[cfg(feature = "ntpv5")]
    fn decode_draft_identification(
        message: &'a [u8],
        extension_header_version: ExtensionHeaderVersion,
    ) -> Result<Self, ParsingError<std::convert::Infallible>> {
        let di = match core::str::from_utf8(message) {
            Ok(di) if di.is_ascii() => di,
            _ => return Err(super::v5::V5Error::InvalidDraftIdentification.into()),
        };

        let di = match extension_header_version {
            ExtensionHeaderVersion::V4 => di.trim_end_matches('\0'),
            ExtensionHeaderVersion::V5 => di,
        };

        Ok(ExtensionField::DraftIdentification(Cow::Borrowed(di)))
    }

    fn decode(
        raw: RawExtensionField<'a>,
        #[cfg_attr(not(feature = "ntpv5"), allow(unused_variables))]
        extension_header_version: ExtensionHeaderVersion,
    ) -> Result<Self, ParsingError<std::convert::Infallible>> {
        type EF<'a> = ExtensionField<'a>;
        type TypeId = ExtensionFieldTypeId;

        let message = &raw.message_bytes;

        match raw.type_id {
            TypeId::UniqueIdentifier => EF::decode_unique_identifier(message),
            TypeId::NtsCookie => EF::decode_nts_cookie(message),
            TypeId::NtsCookiePlaceholder => EF::decode_nts_cookie_placeholder(message),
            #[cfg(feature = "ntpv5")]
            TypeId::DraftIdentification => {
                EF::decode_draft_identification(message, extension_header_version)
            }
            #[cfg(feature = "ntpv5")]
            TypeId::ReferenceIdRequest => Ok(ReferenceIdRequest::decode(message)?.into()),
            #[cfg(feature = "ntpv5")]
            TypeId::ReferenceIdResponse => Ok(ReferenceIdResponse::decode(message).into()),
            type_id => EF::decode_unknown(type_id.to_type_id(), message),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct ExtensionFieldData<'a> {
    pub(super) authenticated: Vec<ExtensionField<'a>>,
    pub(super) encrypted: Vec<ExtensionField<'a>>,
    pub(super) untrusted: Vec<ExtensionField<'a>>,
}

#[derive(Debug)]
pub(super) struct DeserializedExtensionField<'a> {
    pub(super) efdata: ExtensionFieldData<'a>,
    pub(super) remaining_bytes: &'a [u8],
    pub(super) cookie: Option<DecodedServerCookie>,
}

#[derive(Debug)]
pub(super) struct InvalidNtsExtensionField<'a> {
    pub(super) efdata: ExtensionFieldData<'a>,
    pub(super) remaining_bytes: &'a [u8],
}

impl<'a> ExtensionFieldData<'a> {
    pub(super) fn into_owned(self) -> ExtensionFieldData<'static> {
        let map_into_owned =
            |vec: Vec<ExtensionField>| vec.into_iter().map(ExtensionField::into_owned).collect();

        ExtensionFieldData {
            authenticated: map_into_owned(self.authenticated),
            encrypted: map_into_owned(self.encrypted),
            untrusted: map_into_owned(self.untrusted),
        }
    }

    pub(super) fn serialize(
        &self,
        w: &mut Cursor<&mut [u8]>,
        cipher: &(impl CipherProvider + ?Sized),
        version: ExtensionHeaderVersion,
    ) -> std::io::Result<()> {
        if !self.authenticated.is_empty() || !self.encrypted.is_empty() {
            let cipher = match cipher.get(&self.authenticated) {
                Some(cipher) => cipher,
                None => return Err(std::io::Error::new(std::io::ErrorKind::Other, "no cipher")),
            };

            // the authenticated extension fields are always followed by the encrypted extension
            // field. We don't (currently) encode a MAC, so the minimum size per RFC 7822 is 16 octets
            let minimum_size = 16;

            for field in &self.authenticated {
                field.serialize(&mut *w, minimum_size, version)?;
            }

            // RFC 8915, section 5.5: contrary to the RFC 7822 requirement that fields have a minimum length of 16 or 28 octets,
            // encrypted extension fields MAY be arbitrarily short (but still MUST be a multiple of 4 octets in length)
            // hence we don't provide a minimum size here
            ExtensionField::encode_encrypted(w, &self.encrypted, cipher.as_ref(), version)?;
        }

        // per RFC 7822, section 7.5.1.4.
        let mut it = self.untrusted.iter().peekable();
        while let Some(field) = it.next() {
            let is_last = it.peek().is_none();
            let minimum_size = match version {
                ExtensionHeaderVersion::V4 if is_last => 28,
                ExtensionHeaderVersion::V4 => 16,
                #[cfg(feature = "ntpv5")]
                ExtensionHeaderVersion::V5 => 4,
            };
            field.serialize(&mut *w, minimum_size, version)?;
        }

        Ok(())
    }

    #[allow(clippy::type_complexity)]
    pub(super) fn deserialize(
        data: &'a [u8],
        header_size: usize,
        cipher: &(impl CipherProvider + ?Sized),
        version: ExtensionHeaderVersion,
    ) -> Result<DeserializedExtensionField<'a>, ParsingError<InvalidNtsExtensionField<'a>>> {
        use ExtensionField::InvalidNtsEncryptedField;

        let mut efdata = Self::default();
        let mut size = 0;
        let mut is_valid_nts = true;
        let mut cookie = None;
        let mac_size = match version {
            ExtensionHeaderVersion::V4 => Mac::MAXIMUM_SIZE,
            #[cfg(feature = "ntpv5")]
            ExtensionHeaderVersion::V5 => 0,
        };

        for field in RawExtensionField::deserialize_sequence(
            &data[header_size..],
            mac_size,
            RawExtensionField::V4_UNENCRYPTED_MINIMUM_SIZE,
            version,
        ) {
            let (offset, field) = field.map_err(super::error::ParsingError::generalize)?;
            size = offset + field.wire_length(version);
            if field.type_id == ExtensionFieldTypeId::NtsEncryptedField {
                let encrypted = RawEncryptedField::from_message_bytes(field.message_bytes)
                    .map_err(super::error::ParsingError::generalize)?;

                let cipher = if let Some(cipher) = cipher.get(&efdata.untrusted) { cipher } else {
                    efdata.untrusted.push(InvalidNtsEncryptedField);
                    is_valid_nts = false;
                    continue;
                };

                let encrypted_fields = match encrypted.decrypt(
                    cipher.as_ref(),
                    &data[..header_size + offset],
                    version,
                ) {
                    Ok(encrypted_fields) => encrypted_fields,
                    Err(e) => {
                        // early return if it's anything but a decrypt error
                        e.get_decrypt_error()?;

                        efdata.untrusted.push(InvalidNtsEncryptedField);
                        is_valid_nts = false;
                        continue;
                    }
                };

                // for the current ciphers we allow in non-test code,
                // the nonce should always be 16 bytes
                debug_assert_eq!(encrypted.nonce.len(), 16);

                efdata.encrypted.extend(encrypted_fields);
                cookie = match cipher {
                    super::crypto::CipherHolder::DecodedServerCookie(cookie) => Some(cookie),
                    super::crypto::CipherHolder::Other(_) => None,
                };

                // All previous untrusted fields are now validated
                efdata.authenticated.append(&mut efdata.untrusted);
            } else {
                let field =
                    ExtensionField::decode(field, version).map_err(super::error::ParsingError::generalize)?;
                efdata.untrusted.push(field);
            }
        }

        let remaining_bytes = &data[header_size + size..];

        if is_valid_nts {
            let result = DeserializedExtensionField {
                efdata,
                remaining_bytes,
                cookie,
            };

            Ok(result)
        } else {
            let result = InvalidNtsExtensionField {
                efdata,
                remaining_bytes,
            };

            Err(ParsingError::DecryptError(result))
        }
    }
}

struct RawEncryptedField<'a> {
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}

impl<'a> RawEncryptedField<'a> {
    fn from_message_bytes(
        message_bytes: &'a [u8],
    ) -> Result<Self, ParsingError<std::convert::Infallible>> {
        use ParsingError::IncorrectLength;

        let [b0, b1, b2, b3, ref rest @ ..] = message_bytes[..] else {
            return Err(IncorrectLength);
        };

        let nonce_length = u16::from_be_bytes([b0, b1]) as usize;
        let ciphertext_length = u16::from_be_bytes([b2, b3]) as usize;

        let nonce = rest.get(..nonce_length).ok_or(IncorrectLength)?;

        // skip the lengths and the nonce. pad to a multiple of 4
        let ciphertext_start = 4 + next_multiple_of_u16(nonce_length as u16, 4) as usize;

        let ciphertext = message_bytes
            .get(ciphertext_start..ciphertext_start + ciphertext_length)
            .ok_or(IncorrectLength)?;

        Ok(Self { nonce, ciphertext })
    }

    fn decrypt(
        &self,
        cipher: &dyn Cipher,
        aad: &[u8],
        version: ExtensionHeaderVersion,
    ) -> Result<Vec<ExtensionField<'a>>, ParsingError<ExtensionField<'a>>> {
        let plaintext = match cipher.decrypt(self.nonce, self.ciphertext, aad) {
            Ok(plain) => plain,
            Err(_) => {
                return Err(ParsingError::DecryptError(
                    ExtensionField::InvalidNtsEncryptedField,
                ));
            }
        };

        RawExtensionField::deserialize_sequence(
            &plaintext,
            0,
            RawExtensionField::BARE_MINIMUM_SIZE,
            version,
        )
        .map(|encrypted_field| {
            let encrypted_field = encrypted_field.map_err(super::error::ParsingError::generalize)?.1;
            if encrypted_field.type_id == ExtensionFieldTypeId::NtsEncryptedField {
                // TODO: Discuss whether we want this check
                Err(ParsingError::MalformedNtsExtensionFields)
            } else {
                Ok(ExtensionField::decode(encrypted_field, version)
                    .map_err(super::error::ParsingError::generalize)?
                    .into_owned())
            }
        })
        .collect()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ExtensionHeaderVersion {
    V4,
    #[cfg(feature = "ntpv5")]
    V5,
}

#[cfg(feature = "__internal-fuzz")]
impl<'a> arbitrary::Arbitrary<'a> for ExtensionHeaderVersion {
    #[cfg(not(feature = "ntpv5"))]
    fn arbitrary(_u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::V4)
    }

    #[cfg(feature = "ntpv5")]
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(if bool::arbitrary(u)? {
            Self::V4
        } else {
            Self::V5
        })
    }
}

#[derive(Debug)]
struct RawExtensionField<'a> {
    type_id: ExtensionFieldTypeId,
    // bytes of the value and any padding. Does not include the header (field type and length)
    // https://www.rfc-editor.org/rfc/rfc5905.html#section-7.5
    message_bytes: &'a [u8],
}

impl<'a> RawExtensionField<'a> {
    const BARE_MINIMUM_SIZE: usize = 4;
    const V4_UNENCRYPTED_MINIMUM_SIZE: usize = 4;

    fn wire_length(&self, version: ExtensionHeaderVersion) -> usize {
        // field type + length + value + padding
        let length = 2 + 2 + self.message_bytes.len();

        if version == ExtensionHeaderVersion::V4 {
            // All extension fields are zero-padded to a word (four octets) boundary.
            //
            // message_bytes should include this padding, so this should already be true
            debug_assert_eq!(length % 4, 0);
        }

        next_multiple_of_usize(length, 4)
    }

    fn deserialize(
        data: &'a [u8],
        minimum_size: usize,
        version: ExtensionHeaderVersion,
    ) -> Result<Self, ParsingError<std::convert::Infallible>> {
        use ParsingError::IncorrectLength;

        let [b0, b1, b2, b3, ..] = data[..] else {
            return Err(IncorrectLength);
        };

        let type_id = u16::from_be_bytes([b0, b1]);

        // The Length field is a 16-bit unsigned integer that indicates the length of
        // the entire extension field in octets, including the Padding field.
        let field_length = u16::from_be_bytes([b2, b3]) as usize;

        if field_length < minimum_size {
            return Err(IncorrectLength);
        }

        // In NTPv4: padding is up to a multiple of 4 bytes, so a valid field length is divisible by 4
        if version == ExtensionHeaderVersion::V4 && field_length % 4 != 0 {
            return Err(IncorrectLength);
        }

        // In NTPv5: There must still be enough room in the packet for data + padding
        data.get(4..next_multiple_of_usize(field_length, 4))
            .ok_or(IncorrectLength)?;

        // because the field length includes padding, the message bytes may not exactly match the input
        let message_bytes = data.get(4..field_length).ok_or(IncorrectLength)?;

        Ok(Self {
            type_id: ExtensionFieldTypeId::from_type_id(type_id),
            message_bytes,
        })
    }

    fn deserialize_sequence(
        buffer: &'a [u8],
        cutoff: usize,
        minimum_size: usize,
        version: ExtensionHeaderVersion,
    ) -> impl Iterator<
        Item = Result<(usize, RawExtensionField<'a>), ParsingError<std::convert::Infallible>>,
    > + 'a {
        ExtensionFieldStreamer {
            buffer,
            cutoff,
            minimum_size,
            offset: 0,
            version,
        }
    }
}
struct ExtensionFieldStreamer<'a> {
    buffer: &'a [u8],
    cutoff: usize,
    minimum_size: usize,
    offset: usize,
    version: ExtensionHeaderVersion,
}

impl<'a> Iterator for ExtensionFieldStreamer<'a> {
    type Item = Result<(usize, RawExtensionField<'a>), ParsingError<std::convert::Infallible>>;

    fn next(&mut self) -> Option<Self::Item> {
        let remaining = &self.buffer.get(self.offset..)?;

        if remaining.len() <= self.cutoff {
            return None;
        }

        match RawExtensionField::deserialize(remaining, self.minimum_size, self.version) {
            Ok(field) => {
                let offset = self.offset;
                self.offset += field.wire_length(self.version);
                Some(Ok((offset, field)))
            }
            Err(error) => {
                self.offset = self.buffer.len();
                Some(Err(error))
            }
        }
    }
}

const fn next_multiple_of_u16(lhs: u16, rhs: u16) -> u16 {
    match lhs % rhs {
        0 => lhs,
        r => lhs + (rhs - r),
    }
}

const fn next_multiple_of_usize(lhs: usize, rhs: usize) -> usize {
    match lhs % rhs {
        0 => lhs,
        r => lhs + (rhs - r),
    }
}

#[cfg(test)]
mod tests {
    use crate::{keyset::KeySet, packet::AesSivCmac256};

    use super::*;

    #[test]
    fn roundtrip_ef_typeid() {
        for i in 0..=u16::MAX {
            let a = ExtensionFieldTypeId::from_type_id(i);
            assert_eq!(i, a.to_type_id());
        }
    }

    #[test]
    fn test_unique_identifier() {
        let identifier: Vec<_> = (0..16).collect();
        let mut w = vec![];
        ExtensionField::encode_unique_identifier(
            &mut w,
            &identifier,
            0,
            ExtensionHeaderVersion::V4,
        )
        .unwrap();

        assert_eq!(
            w,
            &[1, 4, 0, 20, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn test_nts_cookie() {
        let cookie: Vec<_> = (0..16).collect();
        let mut w = vec![];
        ExtensionField::encode_nts_cookie(&mut w, &cookie, 0, ExtensionHeaderVersion::V4).unwrap();

        assert_eq!(
            w,
            &[2, 4, 0, 20, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn test_nts_cookie_placeholder() {
        const COOKIE_LENGTH: usize = 16;

        let mut w = vec![];
        ExtensionField::encode_nts_cookie_placeholder(
            &mut w,
            COOKIE_LENGTH as u16,
            0,
            ExtensionHeaderVersion::V4,
        )
        .unwrap();

        assert_eq!(
            w,
            &[3, 4, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]
        );

        let raw = RawExtensionField {
            type_id: ExtensionFieldTypeId::NtsCookiePlaceholder,
            message_bytes: &[1; COOKIE_LENGTH],
        };
        let output = ExtensionField::decode(raw, ExtensionHeaderVersion::V4).unwrap_err();

        assert!(matches!(output, ParsingError::MalformedCookiePlaceholder));

        let raw = RawExtensionField {
            type_id: ExtensionFieldTypeId::NtsCookiePlaceholder,
            message_bytes: &[0; COOKIE_LENGTH],
        };
        let output = ExtensionField::decode(raw, ExtensionHeaderVersion::V4).unwrap();

        let ExtensionField::NtsCookiePlaceholder { cookie_length } = output else {
            panic!("incorrect variant");
        };

        assert_eq!(cookie_length, 16);
    }

    #[test]
    fn test_unknown() {
        let data: Vec<_> = (0..16).collect();
        let mut w = vec![];
        ExtensionField::encode_unknown(&mut w, 42, &data, 0, ExtensionHeaderVersion::V4).unwrap();

        assert_eq!(
            w,
            &[0, 42, 0, 20, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[cfg(feature = "ntpv5")]
    #[test]
    fn draft_identification() {
        let test_id = crate::packet::v5::DRAFT_VERSION;
        let len = u16::try_from(4 + test_id.len()).unwrap();
        let mut data = vec![];
        data.extend(&[0xF5, 0xFF]); // Type
        data.extend(&len.to_be_bytes()); // Length
        data.extend(test_id.as_bytes()); // Payload
        data.extend(&[0]); // Padding

        let raw = RawExtensionField::deserialize(&data, 4, ExtensionHeaderVersion::V5).unwrap();
        let ef = ExtensionField::decode(raw, ExtensionHeaderVersion::V4).unwrap();

        let ExtensionField::DraftIdentification(ref parsed) = ef else {
            panic!("Unexpected extension field {ef:?}... expected DraftIdentification");
        };

        assert_eq!(parsed, test_id);

        let mut out = vec![];
        ef.serialize(&mut out, 4, ExtensionHeaderVersion::V5)
            .unwrap();

        assert_eq!(&out, &data);
    }

    #[cfg(feature = "ntpv5")]
    #[test]
    fn extension_field_length() {
        let data: Vec<_> = (0..21).collect();
        let mut w = vec![];
        ExtensionField::encode_unknown(&mut w, 42, &data, 16, ExtensionHeaderVersion::V4).unwrap();
        let raw: RawExtensionField<'_> =
            RawExtensionField::deserialize(&w, 16, ExtensionHeaderVersion::V4).unwrap();

        // v4 extension field header length includes padding bytes
        assert_eq!(w[3], 28);
        assert_eq!(w.len(), 28);
        assert_eq!(raw.message_bytes.len(), 24);
        assert_eq!(raw.wire_length(ExtensionHeaderVersion::V4), 28);

        let mut w = vec![];
        ExtensionField::encode_unknown(&mut w, 42, &data, 16, ExtensionHeaderVersion::V5).unwrap();
        let raw: RawExtensionField<'_> =
            RawExtensionField::deserialize(&w, 16, ExtensionHeaderVersion::V5).unwrap();

        // v5 extension field header length does not include padding bytes
        assert_eq!(w[3], 25);
        assert_eq!(w.len(), 28);
        assert_eq!(raw.message_bytes.len(), 21);
        assert_eq!(raw.wire_length(ExtensionHeaderVersion::V5), 28);
    }

    #[test]
    fn extension_field_minimum_size() {
        let minimum_size = 32;
        let expected_size = minimum_size as usize;
        let data: Vec<_> = (0..16).collect();

        let mut w = vec![];
        ExtensionField::encode_unique_identifier(
            &mut w,
            &data,
            minimum_size,
            ExtensionHeaderVersion::V4,
        )
        .unwrap();
        assert_eq!(w.len(), expected_size);

        let mut w = vec![];
        ExtensionField::encode_nts_cookie(&mut w, &data, minimum_size, ExtensionHeaderVersion::V4)
            .unwrap();
        assert_eq!(w.len(), expected_size);

        let mut w = vec![];
        ExtensionField::encode_nts_cookie_placeholder(
            &mut w,
            data.len() as u16,
            minimum_size,
            ExtensionHeaderVersion::V4,
        )
        .unwrap();
        assert_eq!(w.len(), expected_size);

        let mut w = vec![];
        ExtensionField::encode_unknown(&mut w, 42, &data, minimum_size, ExtensionHeaderVersion::V4)
            .unwrap();
        assert_eq!(w.len(), expected_size);

        // NOTE: encrypted fields do not have a minimum_size
    }

    #[test]
    fn extension_field_padding() {
        let minimum_size = 0;
        let expected_size = 20;
        let data: Vec<_> = (0..15).collect(); // 15 bytes, so padding is needed

        let mut w = vec![];
        ExtensionField::encode_unique_identifier(
            &mut w,
            &data,
            minimum_size,
            ExtensionHeaderVersion::V4,
        )
        .unwrap();
        assert_eq!(w.len(), expected_size);

        let mut w = vec![];
        ExtensionField::encode_nts_cookie(&mut w, &data, minimum_size, ExtensionHeaderVersion::V4)
            .unwrap();
        assert_eq!(w.len(), expected_size);

        let mut w = vec![];
        ExtensionField::encode_nts_cookie_placeholder(
            &mut w,
            data.len() as u16,
            minimum_size,
            ExtensionHeaderVersion::V4,
        )
        .unwrap();
        assert_eq!(w.len(), expected_size);

        let mut w = vec![];
        ExtensionField::encode_unknown(&mut w, 42, &data, minimum_size, ExtensionHeaderVersion::V4)
            .unwrap();
        assert_eq!(w.len(), expected_size);

        let mut w = [0u8; 128];
        let mut cursor = Cursor::new(w.as_mut_slice());
        let c2s = [0; 32];
        let cipher = AesSivCmac256::new(c2s.into());
        let fields_to_encrypt = [ExtensionField::UniqueIdentifier(Cow::Borrowed(
            data.as_slice(),
        ))];
        ExtensionField::encode_encrypted(
            &mut cursor,
            &fields_to_encrypt,
            &cipher,
            ExtensionHeaderVersion::V4,
        )
        .unwrap();
        assert_eq!(
            cursor.position() as usize,
            2 + 6 + c2s.len() + expected_size
        );
    }

    #[test]
    fn nonce_padding() {
        let nonce_length = 11;
        let cipher = crate::packet::crypto::IdentityCipher::new(nonce_length);

        // multiple of 4; no padding is needed
        let fields_to_encrypt = [ExtensionField::Unknown {
            type_id: 42u16,
            data: Cow::Borrowed(&[1, 2, 3, 4]),
        }];

        // 6 bytes of data, rounded up to a multiple of 4
        let plaintext_length = 8;

        let mut w = [0u8; 128];
        let mut cursor = Cursor::new(w.as_mut_slice());
        ExtensionField::encode_encrypted(
            &mut cursor,
            &fields_to_encrypt,
            &cipher,
            ExtensionHeaderVersion::V4,
        )
        .unwrap();

        let expected_length = 2 + 6 + next_multiple_of_usize(nonce_length, 4) + plaintext_length;
        assert_eq!(cursor.position() as usize, expected_length,);

        let message_bytes = &w.as_ref()[..expected_length];

        let mut it = RawExtensionField::deserialize_sequence(
            message_bytes,
            0,
            0,
            ExtensionHeaderVersion::V4,
        );
        let field = it.next().unwrap().unwrap();
        assert!(it.next().is_none());

        match field {
            (
                0,
                RawExtensionField {
                    type_id: ExtensionFieldTypeId::NtsEncryptedField,
                    message_bytes,
                },
            ) => {
                let raw = RawEncryptedField::from_message_bytes(message_bytes).unwrap();
                let decrypted_fields = raw
                    .decrypt(&cipher, &[], ExtensionHeaderVersion::V4)
                    .unwrap();
                assert_eq!(decrypted_fields, fields_to_encrypt);
            }
            _ => panic!("invalid"),
        }
    }

    #[test]
    fn deserialize_extension_field_data_no_cipher() {
        let cookie = ExtensionField::NtsCookie(Cow::Borrowed(&[0; 16]));
        let cipher = crate::packet::crypto::NoCipher;

        // cause an error when the cipher is needed
        {
            let data = ExtensionFieldData {
                authenticated: vec![cookie.clone()],
                encrypted: vec![],
                untrusted: vec![],
            };

            let mut w = [0u8; 128];
            let mut cursor = Cursor::new(w.as_mut_slice());
            assert!(data
                .serialize(&mut cursor, &cipher, ExtensionHeaderVersion::V4)
                .is_err());
        }

        // but succeed when the cipher is not needed
        {
            let data = ExtensionFieldData {
                authenticated: vec![],
                encrypted: vec![],
                untrusted: vec![cookie.clone()],
            };

            let mut w = [0u8; 128];
            let mut cursor = Cursor::new(w.as_mut_slice());
            assert!(data
                .serialize(&mut cursor, &cipher, ExtensionHeaderVersion::V4)
                .is_ok());
        }
    }

    #[test]
    fn serialize_untrusted_fields() {
        let cookie = ExtensionField::NtsCookie(Cow::Borrowed(&[0; 16]));

        let data = ExtensionFieldData {
            authenticated: vec![],
            encrypted: vec![],
            untrusted: vec![cookie.clone(), cookie],
        };

        let nonce_length = 11;
        let cipher = crate::packet::crypto::IdentityCipher::new(nonce_length);

        let mut w = [0u8; 128];
        let mut cursor = Cursor::new(w.as_mut_slice());
        data.serialize(&mut cursor, &cipher, ExtensionHeaderVersion::V4)
            .unwrap();

        let n = cursor.position() as usize;
        let slice = &w.as_slice()[..n];

        // the cookie we provide is `2 + 2 + 16 = 20` bytes
        let expected_length = Ord::max(20, 28) + Ord::max(20, 16);
        assert_eq!(slice.len(), expected_length);
    }

    #[test]
    fn serialize_untrusted_fields_smaller_than_minimum() {
        let cookie = ExtensionField::NtsCookie(Cow::Borrowed(&[0; 4]));

        let data = ExtensionFieldData {
            authenticated: vec![],
            encrypted: vec![],
            untrusted: vec![cookie.clone(), cookie],
        };

        let nonce_length = 11;
        let cipher = crate::packet::crypto::IdentityCipher::new(nonce_length);

        let mut w = [0u8; 128];
        let mut cursor = Cursor::new(w.as_mut_slice());
        data.serialize(&mut cursor, &cipher, ExtensionHeaderVersion::V4)
            .unwrap();

        let n = cursor.position() as usize;
        let slice = &w.as_slice()[..n];

        // now we hit the minimum widths of extension fields
        // let minimum_size = if is_last { 28 } else { 16 };
        assert_eq!(slice.len(), 28 + 16);
    }

    #[test]
    fn deserialize_without_cipher() {
        let cookie = ExtensionField::NtsCookie(Cow::Borrowed(&[0; 32]));

        let data = ExtensionFieldData {
            authenticated: vec![],
            encrypted: vec![cookie],
            untrusted: vec![],
        };

        let nonce_length = 11;
        let cipher = crate::packet::crypto::IdentityCipher::new(nonce_length);

        let mut w = [0u8; 128];
        let mut cursor = Cursor::new(w.as_mut_slice());
        data.serialize(&mut cursor, &cipher, ExtensionHeaderVersion::V4)
            .unwrap();

        let n = cursor.position() as usize;
        let slice = &w.as_slice()[..n];

        let cipher = crate::packet::crypto::NoCipher;

        let result = ExtensionFieldData::deserialize(slice, 0, &cipher, ExtensionHeaderVersion::V4)
            .unwrap_err();

        let ParsingError::DecryptError(InvalidNtsExtensionField {
            efdata,
            remaining_bytes,
        }) = result
        else {
            panic!("invalid variant");
        };

        let invalid = ExtensionField::InvalidNtsEncryptedField;
        assert_eq!(efdata.authenticated, &[]);
        assert_eq!(efdata.encrypted, &[]);
        assert_eq!(efdata.untrusted, &[invalid]);

        assert_eq!(remaining_bytes, &[]);
    }

    #[test]
    fn deserialize_different_cipher() {
        let cookie = ExtensionField::NtsCookie(Cow::Borrowed(&[0; 32]));

        let data = ExtensionFieldData {
            authenticated: vec![],
            encrypted: vec![cookie],
            untrusted: vec![],
        };

        let nonce_length = 11;
        let cipher = crate::packet::crypto::IdentityCipher::new(nonce_length);

        let mut w = [0u8; 128];
        let mut cursor = Cursor::new(w.as_mut_slice());
        data.serialize(&mut cursor, &cipher, ExtensionHeaderVersion::V4)
            .unwrap();

        let n = cursor.position() as usize;
        let slice = &w.as_slice()[..n];

        // now use a different (valid) cipher for deserialization
        let c2s = [0; 32];
        let cipher = AesSivCmac256::new(c2s.into());

        let result = ExtensionFieldData::deserialize(slice, 0, &cipher, ExtensionHeaderVersion::V4)
            .unwrap_err();

        let ParsingError::DecryptError(InvalidNtsExtensionField {
            efdata,
            remaining_bytes,
        }) = result
        else {
            panic!("invalid variant");
        };

        let invalid = ExtensionField::InvalidNtsEncryptedField;
        assert_eq!(efdata.authenticated, &[]);
        assert_eq!(efdata.encrypted, &[]);
        assert_eq!(efdata.untrusted, &[invalid]);

        assert_eq!(remaining_bytes, &[]);
    }

    #[test]
    fn deserialize_with_keyset() {
        let keyset = KeySet::new();

        let decoded_server_cookie = crate::keyset::test_cookie();
        let cookie_data = keyset.encode_cookie(&decoded_server_cookie);

        let cookie = ExtensionField::NtsCookie(Cow::Borrowed(&cookie_data));

        let data = ExtensionFieldData {
            authenticated: vec![cookie.clone()],
            encrypted: vec![cookie],
            untrusted: vec![],
        };

        let mut w = [0u8; 256];
        let mut cursor = Cursor::new(w.as_mut_slice());
        data.serialize(&mut cursor, &keyset, ExtensionHeaderVersion::V4)
            .unwrap();

        let n = cursor.position() as usize;
        let slice = &w.as_slice()[..n];

        let result =
            ExtensionFieldData::deserialize(slice, 0, &keyset, ExtensionHeaderVersion::V4).unwrap();

        let DeserializedExtensionField {
            efdata,
            remaining_bytes,
            cookie,
        } = result;

        assert_eq!(efdata.authenticated.len(), 1);
        assert_eq!(efdata.encrypted.len(), 1);
        assert_eq!(efdata.untrusted, &[]);

        assert_eq!(remaining_bytes, &[]);

        assert!(cookie.is_some());
    }
}
