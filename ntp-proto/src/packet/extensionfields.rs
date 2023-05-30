use std::{
    borrow::Cow,
    io::{Cursor, Write},
};

use crate::{arrayvec::ArrayVec, DecodedServerCookie};

use super::{error::ParsingError, Cipher, CipherProvider, Mac};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ExtensionFieldTypeId {
    UniqueIdentifier,
    NtsCookie,
    NtsCookiePlaceholder,
    NtsEncryptedField,
    Unknown { type_id: u16 },
}

impl ExtensionFieldTypeId {
    fn from_type_id(type_id: u16) -> Self {
        match type_id {
            0x104 => Self::UniqueIdentifier,
            0x204 => Self::NtsCookie,
            0x304 => Self::NtsCookiePlaceholder,
            0x404 => Self::NtsEncryptedField,
            _ => Self::Unknown { type_id },
        }
    }

    fn to_type_id(self) -> u16 {
        match self {
            ExtensionFieldTypeId::UniqueIdentifier => 0x104,
            ExtensionFieldTypeId::NtsCookie => 0x204,
            ExtensionFieldTypeId::NtsCookiePlaceholder => 0x304,
            ExtensionFieldTypeId::NtsEncryptedField => 0x404,
            ExtensionFieldTypeId::Unknown { type_id } => type_id,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ExtensionField<'a> {
    UniqueIdentifier(Cow<'a, [u8]>),
    NtsCookie(Cow<'a, [u8]>),
    NtsCookiePlaceholder { cookie_length: u16 },
    InvalidNtsEncryptedField,
    Unknown { type_id: u16, data: Cow<'a, [u8]> },
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
    pub fn into_owned(self) -> ExtensionField<'static> {
        use ExtensionField::*;

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
        }
    }

    fn serialize<W: std::io::Write>(&self, w: &mut W, minimum_size: u16) -> std::io::Result<()> {
        use ExtensionField::*;

        match self {
            Unknown { type_id, data } => Self::encode_unknown(w, *type_id, data, minimum_size),
            UniqueIdentifier(identifier) => {
                Self::encode_unique_identifier(w, identifier, minimum_size)
            }
            NtsCookie(cookie) => Self::encode_nts_cookie(w, cookie, minimum_size),
            NtsCookiePlaceholder {
                cookie_length: body_length,
            } => Self::encode_nts_cookie_placeholder(w, *body_length, minimum_size),
            InvalidNtsEncryptedField => Err(std::io::ErrorKind::Other.into()),
        }
    }

    #[cfg(feature = "fuzz")]
    pub fn serialize_pub<W: std::io::Write>(
        &self,
        w: &mut W,
        minimum_size: u16,
    ) -> std::io::Result<()> {
        self.serialize(w, minimum_size)
    }

    fn encode_framing<W: std::io::Write>(
        w: &mut W,
        ef_id: ExtensionFieldTypeId,
        data_length: usize,
        minimum_size: u16,
    ) -> std::io::Result<()> {
        if data_length > u16::MAX as usize - 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Extension field too long",
            ));
        }

        // u16 for the type_id, u16 for the length
        let header_width = 4;

        let actual_length =
            next_multiple_of_u16((data_length as u16 + header_width).max(minimum_size), 4);
        w.write_all(&ef_id.to_type_id().to_be_bytes())?;
        w.write_all(&actual_length.to_be_bytes())
    }

    fn encode_padding<W: std::io::Write>(
        w: &mut W,
        data_length: usize,
        minimum_size: u16,
    ) -> std::io::Result<()> {
        if data_length > u16::MAX as usize - 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Extension field too long",
            ));
        }

        // u16 for the type_id, u16 for the length
        let header_width = 4;

        let actual_length =
            next_multiple_of_u16((data_length as u16 + header_width).max(minimum_size), 4);

        Self::write_zeros(w, actual_length - (data_length as u16) - 4)
    }

    fn write_zeros(w: &mut impl std::io::Write, n: u16) -> std::io::Result<()> {
        let mut remaining = n;
        let padding_bytes = [0_u8; 32];
        while remaining > 0 {
            let added = usize::min(remaining as usize, padding_bytes.len());
            w.write_all(&padding_bytes[..added])?;

            remaining -= added as u16;
        }

        Ok(())
    }

    fn encode_unique_identifier<W: std::io::Write>(
        w: &mut W,
        identifier: &[u8],
        minimum_size: u16,
    ) -> std::io::Result<()> {
        Self::encode_framing(
            w,
            ExtensionFieldTypeId::UniqueIdentifier,
            identifier.len(),
            minimum_size,
        )?;
        w.write_all(identifier)?;
        Self::encode_padding(w, identifier.len(), minimum_size)
    }

    fn encode_nts_cookie<W: std::io::Write>(
        w: &mut W,
        cookie: &[u8],
        minimum_size: u16,
    ) -> std::io::Result<()> {
        Self::encode_framing(
            w,
            ExtensionFieldTypeId::NtsCookie,
            cookie.len(),
            minimum_size,
        )?;

        w.write_all(cookie)?;

        Self::encode_padding(w, cookie.len(), minimum_size)?;

        Ok(())
    }

    fn encode_nts_cookie_placeholder<W: std::io::Write>(
        w: &mut W,
        cookie_length: u16,
        minimum_size: u16,
    ) -> std::io::Result<()> {
        Self::encode_framing(
            w,
            ExtensionFieldTypeId::NtsCookiePlaceholder,
            cookie_length as usize,
            minimum_size,
        )?;

        Self::write_zeros(w, cookie_length)?;

        Self::encode_padding(w, cookie_length as usize, minimum_size)?;

        Ok(())
    }

    fn encode_unknown<W: std::io::Write>(
        w: &mut W,
        type_id: u16,
        data: &[u8],
        minimum_size: u16,
    ) -> std::io::Result<()> {
        Self::encode_framing(
            w,
            ExtensionFieldTypeId::Unknown { type_id },
            data.len(),
            minimum_size,
        )?;

        w.write_all(data)?;

        Self::encode_padding(w, data.len(), minimum_size)?;

        Ok(())
    }

    fn encode_encrypted(
        w: &mut Cursor<&mut [u8]>,
        fields_to_encrypt: &[ExtensionField],
        cipher: &dyn Cipher,
    ) -> std::io::Result<()> {
        let padding = [0; 4];

        let current_position = w.position();

        let packet_so_far = &w.get_ref()[..current_position as usize];

        // 1024 is our maximum response size, and therefore a safe upper bound on the plaintext length
        let mut plaintext = ArrayVec::<1024>::default();
        for field in fields_to_encrypt {
            // RFC 8915, section 5.5: contrary to the RFC 7822 requirement that fields have a minimum length of 16 or 28 octets,
            // encrypted extension fields MAY be arbitrarily short (but still MUST be a multiple of 4 octets in length)
            let minimum_size = 0;
            field.serialize(&mut plaintext, minimum_size)?;
        }

        let (siv_tag, nonce) = cipher
            .encrypt_in_place_detached(plaintext.as_mut(), packet_so_far)
            .unwrap();
        let ciphertext = plaintext.as_slice();

        w.write_all(
            &ExtensionFieldTypeId::NtsEncryptedField
                .to_type_id()
                .to_be_bytes(),
        )?;

        // NOTE: these are NOT rounded up to a number of words
        let nonce_octet_count = nonce.len();
        let ct_octet_count = siv_tag.len() + ciphertext.len();

        // + 8 for the extension field header (4 bytes) and nonce/cypher text length (2 bytes each)
        let signature_octet_count =
            8 + next_multiple_of_u16((nonce_octet_count + ct_octet_count) as u16, 4);

        w.write_all(&signature_octet_count.to_be_bytes())?;
        w.write_all(&(nonce_octet_count as u16).to_be_bytes())?;
        w.write_all(&(ct_octet_count as u16).to_be_bytes())?;

        w.write_all(&nonce)?;
        let padding_bytes = next_multiple_of_u16(nonce.len() as u16, 4) - nonce.len() as u16;
        w.write_all(&padding[..padding_bytes as usize])?;

        w.write_all(&siv_tag)?;
        w.write_all(ciphertext)?;
        let padding_bytes = next_multiple_of_u16(ct_octet_count as u16, 4) - ct_octet_count as u16;
        w.write_all(&padding[..padding_bytes as usize])?;

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
            Err(ParsingError::IncorrectLength)
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

    fn decode(raw: RawExtensionField<'a>) -> Result<Self, ParsingError<std::convert::Infallible>> {
        type EF<'a> = ExtensionField<'a>;
        type TypeId = ExtensionFieldTypeId;

        let message = &raw.message_bytes;

        match raw.type_id {
            TypeId::UniqueIdentifier => EF::decode_unique_identifier(message),
            TypeId::NtsCookie => EF::decode_nts_cookie(message),
            TypeId::NtsCookiePlaceholder => EF::decode_nts_cookie_placeholder(message),
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

pub(super) struct DeserializedExtensionField<'a> {
    pub(super) efdata: ExtensionFieldData<'a>,
    pub(super) remaining_bytes: &'a [u8],
    pub(super) opt_cookie: Option<Option<DecodedServerCookie>>,
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
    ) -> std::io::Result<()> {
        if !self.authenticated.is_empty() || !self.encrypted.is_empty() {
            let cipher = match cipher.get(&self.authenticated) {
                Some(cipher) => cipher,
                None => return Err(std::io::Error::new(std::io::ErrorKind::Other, "")),
            };

            // the authenticated extension fields are always followed by the encrypted extension
            // field. We don't (currently) encode a MAC, so the minimum size per RFC 7822 is 16 octecs
            let minimum_size = 16;

            for field in &self.authenticated {
                field.serialize(w, minimum_size)?;
            }

            // RFC 8915, section 5.5: contrary to the RFC 7822 requirement that fields have a minimum length of 16 or 28 octets,
            // encrypted extension fields MAY be arbitrarily short (but still MUST be a multiple of 4 octets in length)
            // hence we don't provide a minimum size here
            ExtensionField::encode_encrypted(w, &self.encrypted, cipher.as_ref())?;
        }

        // per RFC 7822, section 7.5.1.4.
        let mut it = self.untrusted.iter().peekable();
        while let Some(field) = it.next() {
            let is_last = it.peek().is_none();
            let minimum_size = if is_last { 28 } else { 16 };
            field.serialize(w, minimum_size)?;
        }

        Ok(())
    }

    #[allow(clippy::type_complexity)]
    pub(super) fn deserialize(
        extension_field_bytes: &'a [u8],
        cipher: &impl CipherProvider,
    ) -> Result<DeserializedExtensionField<'a>, ParsingError<std::convert::Infallible>> {
        let mut this = Self::default();
        let mut size = 0;
        let mut is_valid_nts = true;
        let mut cookie = None;
        for field in RawExtensionField::deserialize_sequence(
            extension_field_bytes,
            Mac::MAXIMUM_SIZE,
            RawExtensionField::V4_UNENCRYPTED_MINIMUM_SIZE,
        ) {
            let field = field?;
            size += field.wire_length();
            match field.type_id {
                ExtensionFieldTypeId::NtsEncryptedField => {
                    let encrypted = RawEncryptedField::from_message_bytes(field.message_bytes)?;

                    let cipher = match cipher.get(&this.untrusted) {
                        Some(cipher) => cipher,
                        None => {
                            this.untrusted
                                .push(ExtensionField::InvalidNtsEncryptedField);
                            is_valid_nts = false;
                            continue;
                        }
                    };

                    let encrypted_fields =
                        match encrypted.decrypt(cipher.as_ref(), field.message_bytes) {
                            Ok(encrypted_fields) => encrypted_fields,
                            Err(e) => {
                                e.get_decrypt_error()?;
                                this.untrusted
                                    .push(ExtensionField::InvalidNtsEncryptedField);
                                is_valid_nts = false;
                                continue;
                            }
                        };

                    this.encrypted.extend(encrypted_fields.into_iter());
                    cookie = match cipher {
                        super::crypto::CipherHolder::DecodedServerCookie(cookie) => Some(cookie),
                        super::crypto::CipherHolder::Other(_) => None,
                    };

                    // All previous untrusted fields are now validated
                    this.authenticated.append(&mut this.untrusted);
                }
                _ => this.untrusted.push(ExtensionField::decode(field)?),
            }
        }

        let result = DeserializedExtensionField {
            efdata: this,
            remaining_bytes: &extension_field_bytes[size..],
            opt_cookie: is_valid_nts.then_some(cookie),
        };

        Ok(result)
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
        use ParsingError::*;

        let [ b0, b1, b2, b3, ref rest @ .. ] = message_bytes[..] else {
            return Err(IncorrectLength);
        };

        let nonce_length = u16::from_be_bytes([b0, b1]) as usize;
        let ciphertext_length = u16::from_be_bytes([b2, b3]) as usize;

        if nonce_length != 16 {
            return Err(IncorrectLength);
        }

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
    ) -> Result<Vec<ExtensionField<'a>>, ParsingError<ExtensionField<'a>>> {
        let plaintext = match cipher.decrypt(self.nonce, self.ciphertext, aad) {
            Ok(plain) => plain,
            Err(_) => {
                return Err(ParsingError::DecryptError(
                    ExtensionField::InvalidNtsEncryptedField,
                ))
            }
        };

        RawExtensionField::deserialize_sequence(&plaintext, 0, RawExtensionField::BARE_MINIMUM_SIZE)
            .map(|encrypted_field| {
                let encrypted_field = encrypted_field.map_err(|e| e.generalize())?;
                if encrypted_field.type_id == ExtensionFieldTypeId::NtsEncryptedField {
                    // TODO: Discuss whether we want this check
                    Err(ParsingError::MalformedNtsExtensionFields)
                } else {
                    Ok(ExtensionField::decode(encrypted_field)
                        .map_err(|e| e.generalize())?
                        .into_owned())
                }
            })
            .collect()
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

    fn wire_length(&self) -> usize {
        // field type + length + value + padding
        let length = 2 + 2 + self.message_bytes.len();

        // All extension fields are zero-padded to a word (four octets) boundary.
        //
        // message_bytes should include this padding, so this should already be true
        debug_assert_eq!(length % 4, 0);

        next_multiple_of_usize(length, 4)
    }

    fn deserialize(
        data: &'a [u8],
        minimum_size: usize,
    ) -> Result<Self, ParsingError<std::convert::Infallible>> {
        use ParsingError::IncorrectLength;

        let [ b0, b1, b2, b3, .. ] = data[..] else {
            return Err(IncorrectLength);
        };

        let type_id = u16::from_be_bytes([b0, b1]);

        // The Length field is a 16-bit unsigned integer that indicates the length of
        // the entire extension field in octets, including the Padding field.
        let field_length = u16::from_be_bytes([b2, b3]) as usize;

        // padding is up to a multiple of 4 bytes, so a valid field length is divisible by 4
        if field_length < minimum_size || field_length % 4 != 0 {
            return Err(ParsingError::IncorrectLength);
        }

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
    ) -> impl Iterator<Item = Result<RawExtensionField<'a>, ParsingError<std::convert::Infallible>>> + 'a
    {
        ExtensionFieldStreamer {
            buffer,
            cutoff,
            minimum_size,
            offset: 0,
        }
    }
}
struct ExtensionFieldStreamer<'a> {
    buffer: &'a [u8],
    cutoff: usize,
    minimum_size: usize,
    offset: usize,
}

impl<'a> Iterator for ExtensionFieldStreamer<'a> {
    type Item = Result<RawExtensionField<'a>, ParsingError<std::convert::Infallible>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.len() - self.offset <= self.cutoff {
            return None;
        }

        match RawExtensionField::deserialize(&self.buffer[self.offset..], self.minimum_size) {
            Ok(field) => {
                self.offset += field.wire_length();
                Some(Ok(field))
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
    use crate::packet::AesSivCmac256;

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
        ExtensionField::encode_unique_identifier(&mut w, &identifier, 0).unwrap();

        assert_eq!(
            w,
            &[1, 4, 0, 20, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn test_nts_cookie() {
        let cookie: Vec<_> = (0..16).collect();
        let mut w = vec![];
        ExtensionField::encode_nts_cookie(&mut w, &cookie, 0).unwrap();

        assert_eq!(
            w,
            &[2, 4, 0, 20, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn test_nts_cookie_placeholder() {
        let mut w = vec![];
        ExtensionField::encode_nts_cookie_placeholder(&mut w, 16, 0).unwrap();

        assert_eq!(
            w,
            &[3, 4, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]
        );
    }

    #[test]
    fn test_unknown() {
        let data: Vec<_> = (0..16).collect();
        let mut w = vec![];
        ExtensionField::encode_unknown(&mut w, 42, &data, 0).unwrap();

        assert_eq!(
            w,
            &[0, 42, 0, 20, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn extension_field_minimum_size() {
        let minimum_size = 32;
        let expected_size = minimum_size as usize;
        let data: Vec<_> = (0..16).collect();

        let mut w = vec![];
        ExtensionField::encode_unique_identifier(&mut w, &data, minimum_size).unwrap();
        assert_eq!(w.len(), expected_size);

        let mut w = vec![];
        ExtensionField::encode_nts_cookie(&mut w, &data, minimum_size).unwrap();
        assert_eq!(w.len(), expected_size);

        let mut w = vec![];
        ExtensionField::encode_nts_cookie_placeholder(&mut w, data.len() as u16, minimum_size)
            .unwrap();
        assert_eq!(w.len(), expected_size);

        let mut w = vec![];
        ExtensionField::encode_unknown(&mut w, 42, &data, minimum_size).unwrap();
        assert_eq!(w.len(), expected_size);

        // NOTE: encryped fields do not have a minimum_size
    }

    #[test]
    fn extension_field_padding() {
        let minimum_size = 0;
        let expected_size = 20;
        let data: Vec<_> = (0..15).collect(); // 15 bytes, so padding is needed

        let mut w = vec![];
        ExtensionField::encode_unique_identifier(&mut w, &data, minimum_size).unwrap();
        assert_eq!(w.len(), expected_size);

        let mut w = vec![];
        ExtensionField::encode_nts_cookie(&mut w, &data, minimum_size).unwrap();
        assert_eq!(w.len(), expected_size);

        let mut w = vec![];
        ExtensionField::encode_nts_cookie_placeholder(&mut w, data.len() as u16, minimum_size)
            .unwrap();
        assert_eq!(w.len(), expected_size);

        let mut w = vec![];
        ExtensionField::encode_unknown(&mut w, 42, &data, minimum_size).unwrap();
        assert_eq!(w.len(), expected_size);

        let mut w = [0u8; 128];
        let mut cursor = Cursor::new(w.as_mut_slice());
        let c2s = [0; 32];
        let cipher = AesSivCmac256::new(c2s.into());
        let fields_to_encrypt = [ExtensionField::UniqueIdentifier(Cow::Borrowed(
            data.as_slice(),
        ))];
        ExtensionField::encode_encrypted(&mut cursor, &fields_to_encrypt, &cipher).unwrap();
        assert_eq!(
            cursor.position() as usize,
            2 + 6 + c2s.len() + expected_size
        );
    }
}
