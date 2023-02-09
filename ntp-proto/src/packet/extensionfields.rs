use std::{
    borrow::Cow,
    io::{Cursor, Write},
};

use aes_siv::{
    aead::{Aead, Payload},
    AeadCore, Nonce,
};

use super::{Cipher, Mac, PacketParsingError};

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
    fn into_owned(self) -> ExtensionField<'static> {
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
        cipher: &Cipher,
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

        let payload = Payload {
            msg: &plaintext,
            aad: packet_so_far,
        };

        let nonce = Cipher::generate_nonce(rand::thread_rng());
        let ct = cipher.encrypt(&nonce, payload).unwrap();

        w.write_all(
            &ExtensionFieldTypeId::NtsEncryptedField
                .to_type_id()
                .to_be_bytes(),
        )?;

        // NOTE: these are NOT rounded up to a number of words
        let nonce_octet_count = nonce.len();
        let ct_octet_count = ct.len();

        // + 8 for the extension field header (4 bytes) and nonce/cypher text length (2 bytes each)
        let signature_octet_count =
            8 + next_multiple_of((nonce_octet_count + ct_octet_count) as u16, 4);

        w.write_all(&signature_octet_count.to_be_bytes())?;
        w.write_all(&(nonce_octet_count as u16).to_be_bytes())?;
        w.write_all(&(ct_octet_count as u16).to_be_bytes())?;

        w.write_all(&nonce)?;
        let padding_bytes = next_multiple_of(nonce.len() as u16, 4) - nonce.len() as u16;
        w.write_all(&padding[..padding_bytes as usize])?;

        w.write_all(ct.as_slice())?;
        let padding_bytes = next_multiple_of(ct.len() as u16, 4) - ct.len() as u16;
        w.write_all(&padding[..padding_bytes as usize])?;

        Ok(())
    }
    fn decode_unique_identifier(message: &'a [u8]) -> Result<Self, PacketParsingError> {
        // The string MUST be at least 32 octets long
        // TODO: Discuss if we really want this check here
        if message.len() < 32 {
            return Err(PacketParsingError::IncorrectLength);
        }

        Ok(ExtensionField::UniqueIdentifier(message[..].into()))
    }

    fn decode_nts_cookie(message: &'a [u8]) -> Result<Self, PacketParsingError> {
        Ok(ExtensionField::NtsCookie(message[..].into()))
    }

    fn decode_nts_cookie_placeholder(message: &'a [u8]) -> Result<Self, PacketParsingError> {
        if message.iter().any(|b| *b != 0) {
            Err(PacketParsingError::IncorrectLength)
        } else {
            Ok(ExtensionField::NtsCookiePlaceholder {
                cookie_length: message.len() as u16,
            })
        }
    }

    fn decode_unknown(type_id: u16, message: &'a [u8]) -> Result<Self, PacketParsingError> {
        Ok(ExtensionField::Unknown {
            type_id,
            data: Cow::Borrowed(message),
        })
    }

    fn decode(raw: RawExtensionField<'a>) -> Result<Self, PacketParsingError> {
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
        cipher: Option<&Cipher>,
    ) -> std::io::Result<()> {
        if !self.authenticated.is_empty() || !self.encrypted.is_empty() {
            let cipher = match cipher {
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
            ExtensionField::encode_encrypted(w, &self.encrypted, cipher)?;
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

    pub(super) fn deserialize(
        data: &'a [u8],
        header_size: usize,
        cipher: Option<&Cipher>,
    ) -> Result<(Self, usize), PacketParsingError> {
        let mut this = Self::default();
        let mut size = 0;
        for field in RawExtensionField::deserialize_sequence(
            &data[header_size..],
            Mac::MAXIMUM_SIZE,
            RawExtensionField::V4_UNENCRYPTED_MINIMUM_SIZE,
        ) {
            let (offset, field) = field?;
            size = offset + field.wire_length();
            match field.type_id {
                ExtensionFieldTypeId::NtsEncryptedField => {
                    let encrypted = RawEncryptedField::from_message_bytes(field.message_bytes)?;
                    let cipher = cipher.ok_or(PacketParsingError::DecryptError)?;

                    // TODO: Discuss whether we want to do this check
                    if !this.authenticated.is_empty() || !this.encrypted.is_empty() {
                        return Err(PacketParsingError::MalformedNtsExtensionFields);
                    }

                    this.encrypted.extend(
                        encrypted
                            .decrypt(cipher, &data[..header_size + offset])?
                            .into_iter(),
                    );

                    // All previous untrusted fields are now validated
                    this.authenticated.append(&mut this.untrusted);
                }
                _ => this.untrusted.push(ExtensionField::decode(field)?),
            }
        }
        Ok((this, size + header_size))
    }
}

struct RawEncryptedField<'a> {
    nonce: &'a Nonce,
    ciphertext: &'a [u8],
}

impl<'a> RawEncryptedField<'a> {
    fn from_message_bytes(message_bytes: &'a [u8]) -> Result<Self, PacketParsingError> {
        use PacketParsingError::*;

        if message_bytes.len() < 4 {
            return Err(IncorrectLength);
        }

        let value = message_bytes;

        if message_bytes.len() < 4 {
            return Err(IncorrectLength);
        }

        let nonce_length = u16::from_be_bytes(value[0..2].try_into().unwrap()) as usize;
        if nonce_length != 16 {
            // for now, only support 16 byte nonces.
            return Err(IncorrectLength);
        }
        let ciphertext_length = u16::from_be_bytes(value[2..4].try_into().unwrap()) as usize;

        if nonce_length != 16 {
            return Err(IncorrectLength);
        }

        let ciphertext_start = 4 + next_multiple_of(nonce_length as u16, 4) as usize;

        let nonce_bytes = value.get(4..4 + nonce_length).ok_or(IncorrectLength)?;

        let ciphertext = value
            .get(ciphertext_start..ciphertext_start + ciphertext_length)
            .ok_or(IncorrectLength)?;

        Ok(Self {
            nonce: Nonce::from_slice(nonce_bytes),
            ciphertext,
        })
    }

    fn decrypt(
        &self,
        cipher: &Cipher,
        aad: &[u8],
    ) -> Result<Vec<ExtensionField<'a>>, PacketParsingError> {
        let payload = Payload {
            msg: self.ciphertext,
            aad,
        };

        let plaintext = match cipher.decrypt(self.nonce, payload) {
            Ok(plain) => plain,
            Err(_) => return Err(PacketParsingError::DecryptError),
        };

        let mut result = vec![];
        for encrypted_field in RawExtensionField::deserialize_sequence(
            &plaintext,
            0,
            RawExtensionField::BARE_MINIMUM_SIZE,
        ) {
            let encrypted_field = encrypted_field?.1;
            if encrypted_field.type_id == ExtensionFieldTypeId::NtsEncryptedField {
                // TODO: Discuss whether we want this check
                return Err(PacketParsingError::MalformedNtsExtensionFields);
            }
            result.push(ExtensionField::decode(encrypted_field)?.into_owned());
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

    fn deserialize(data: &'a [u8], minimum_size: usize) -> Result<Self, PacketParsingError> {
        use PacketParsingError::IncorrectLength;

        if data.len() < 4 {
            return Err(IncorrectLength);
        }

        let type_id = u16::from_be_bytes(data[0..2].try_into().unwrap());
        let field_length = u16::from_be_bytes(data[2..4].try_into().unwrap()) as usize;
        if field_length < minimum_size || field_length % 4 != 0 {
            return Err(PacketParsingError::IncorrectLength);
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
    ) -> impl Iterator<Item = Result<(usize, RawExtensionField<'a>), PacketParsingError>> + 'a {
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
    type Item = Result<(usize, RawExtensionField<'a>), PacketParsingError>;

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
    use aes_siv::{
        aead::{Key, KeyInit},
        Aes128SivAead,
    };

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
        let cipher = Aes128SivAead::new(Key::<Aes128SivAead>::from_slice(c2s.as_slice()));
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
