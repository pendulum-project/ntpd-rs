use std::{
    borrow::Cow,
    io::{Cursor, Write},
};

use crate::DecodedServerCookie;

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
            next_multiple_of((data_length as u16 + header_width).max(minimum_size), 4);
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
            next_multiple_of((data_length as u16 + header_width).max(minimum_size), 4);

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

        let mut plaintext = Vec::new();
        for field in fields_to_encrypt {
            // RFC 8915, section 5.5: contrary to the RFC 7822 requirement that fields have a minimum length of 16 or 28 octets,
            // encrypted extension fields MAY be arbitrarily short (but still MUST be a multiple of 4 octets in length)
            let minimum_size = 0;
            field.serialize(&mut plaintext, minimum_size)?;
        }

        let encryptiondata = cipher.encrypt(&plaintext, packet_so_far).unwrap();

        w.write_all(
            &ExtensionFieldTypeId::NtsEncryptedField
                .to_type_id()
                .to_be_bytes(),
        )?;

        // NOTE: these are NOT rounded up to a number of words
        let nonce_octet_count = encryptiondata.nonce.len();
        let ct_octet_count = encryptiondata.ciphertext.len();

        // + 8 for the extension field header (4 bytes) and nonce/cypher text length (2 bytes each)
        let signature_octet_count =
            8 + next_multiple_of((nonce_octet_count + ct_octet_count) as u16, 4);

        w.write_all(&signature_octet_count.to_be_bytes())?;
        w.write_all(&(nonce_octet_count as u16).to_be_bytes())?;
        w.write_all(&(ct_octet_count as u16).to_be_bytes())?;

        w.write_all(&encryptiondata.nonce)?;
        let padding_bytes = next_multiple_of(encryptiondata.nonce.len() as u16, 4)
            - encryptiondata.nonce.len() as u16;
        w.write_all(&padding[..padding_bytes as usize])?;

        w.write_all(&encryptiondata.ciphertext)?;
        let padding_bytes = next_multiple_of(encryptiondata.ciphertext.len() as u16, 4)
            - encryptiondata.ciphertext.len() as u16;
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
        cipher: &impl CipherProvider,
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
        data: &'a [u8],
        header_size: usize,
        cipher: &impl CipherProvider,
    ) -> Result<
        (Self, usize, Option<DecodedServerCookie>),
        ParsingError<(ExtensionFieldData<'a>, usize)>,
    > {
        let mut this = Self::default();
        let mut size = 0;
        let mut has_invalid_nts = false;
        let mut cookie = None;
        for field in RawExtensionField::deserialize_sequence(
            &data[header_size..],
            Mac::MAXIMUM_SIZE,
            RawExtensionField::V4_UNENCRYPTED_MINIMUM_SIZE,
        ) {
            let (offset, field) = field.map_err(|e| e.generalize())?;
            size = offset + field.wire_length();
            match field.type_id {
                ExtensionFieldTypeId::NtsEncryptedField => {
                    let encrypted = RawEncryptedField::from_message_bytes(field.message_bytes)
                        .map_err(|e| e.generalize())?;
                    let cipher = match cipher.get(&this.untrusted) {
                        Some(cipher) => cipher,
                        None => {
                            this.untrusted
                                .push(ExtensionField::InvalidNtsEncryptedField);
                            has_invalid_nts = true;
                            continue;
                        }
                    };

                    let encrypted_fields =
                        match encrypted.decrypt(cipher.as_ref(), &data[..header_size + offset]) {
                            Ok(encrypted_fields) => encrypted_fields,
                            Err(e) => {
                                e.get_decrypt_error()?;
                                this.untrusted
                                    .push(ExtensionField::InvalidNtsEncryptedField);
                                has_invalid_nts = true;
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
                _ => this
                    .untrusted
                    .push(ExtensionField::decode(field).map_err(|e| e.generalize())?),
            }
        }
        if has_invalid_nts {
            Err(ParsingError::DecryptError((this, size + header_size)))
        } else {
            Ok((this, size + header_size, cookie))
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
        use ParsingError::*;

        if message_bytes.len() < 4 {
            return Err(IncorrectLength);
        }

        let value = message_bytes;

        if message_bytes.len() < 4 {
            return Err(IncorrectLength);
        }

        let nonce_length = u16::from_be_bytes(value[0..2].try_into().unwrap()) as usize;
        let ciphertext_length = u16::from_be_bytes(value[2..4].try_into().unwrap()) as usize;

        if nonce_length != 16 {
            return Err(IncorrectLength);
        }

        let ciphertext_start = 4 + next_multiple_of(nonce_length as u16, 4) as usize;

        let nonce = value.get(4..4 + nonce_length).ok_or(IncorrectLength)?;

        let ciphertext = value
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

        let mut result = vec![];
        for encrypted_field in RawExtensionField::deserialize_sequence(
            &plaintext,
            0,
            RawExtensionField::BARE_MINIMUM_SIZE,
        ) {
            let encrypted_field = encrypted_field.map_err(|e| e.generalize())?.1;
            if encrypted_field.type_id == ExtensionFieldTypeId::NtsEncryptedField {
                // TODO: Discuss whether we want this check
                return Err(ParsingError::MalformedNtsExtensionFields);
            }
            result.push(
                ExtensionField::decode(encrypted_field)
                    .map_err(|e| e.generalize())?
                    .into_owned(),
            );
        }

        Ok(result)
    }
}

#[derive(Debug)]
struct RawExtensionField<'a> {
    type_id: ExtensionFieldTypeId,
    // bytes of just the message: does not include the header or padding
    message_bytes: &'a [u8],
}

impl<'a> RawExtensionField<'a> {
    const BARE_MINIMUM_SIZE: usize = 4;
    const V4_UNENCRYPTED_MINIMUM_SIZE: usize = 4;

    fn wire_length(&self) -> usize {
        // type_id and extension_field_length + data + padding
        4 + self.message_bytes.len()
    }

    fn deserialize(
        data: &'a [u8],
        minimum_size: usize,
    ) -> Result<Self, ParsingError<std::convert::Infallible>> {
        use ParsingError::IncorrectLength;

        if data.len() < 4 {
            return Err(IncorrectLength);
        }

        let type_id = u16::from_be_bytes(data[0..2].try_into().unwrap());
        let field_length = u16::from_be_bytes(data[2..4].try_into().unwrap()) as usize;
        if field_length < minimum_size || field_length % 4 != 0 {
            return Err(ParsingError::IncorrectLength);
        }

        let value = data.get(4..field_length).ok_or(IncorrectLength)?;

        Ok(Self {
            type_id: ExtensionFieldTypeId::from_type_id(type_id),
            message_bytes: value,
        })
    }

    fn deserialize_sequence(
        buffer: &'a [u8],
        cutoff: usize,
        minimum_size: usize,
    ) -> impl Iterator<
        Item = Result<(usize, RawExtensionField<'a>), ParsingError<std::convert::Infallible>>,
    > + 'a {
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
    type Item = Result<(usize, RawExtensionField<'a>), ParsingError<std::convert::Infallible>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.len() - self.offset <= self.cutoff {
            return None;
        }

        match RawExtensionField::deserialize(&self.buffer[self.offset..], self.minimum_size) {
            Ok(field) => {
                let offset = self.offset;
                self.offset += field.wire_length();
                Some(Ok((offset, field)))
            }
            Err(error) => {
                self.offset = self.buffer.len();
                Some(Err(error))
            }
        }
    }
}

const fn next_multiple_of(lhs: u16, rhs: u16) -> u16 {
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
