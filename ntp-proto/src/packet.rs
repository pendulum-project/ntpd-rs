use std::{borrow::Cow, fmt::Display, io::Cursor, io::Write};

use aes_siv::{
    aead::{Aead, Payload},
    Nonce,
};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

use crate::{NtpClock, NtpDuration, NtpTimestamp, PollInterval, ReferenceId, SystemSnapshot};

type Cipher = aes_siv::Aes128SivAead;

#[derive(Debug)]
pub enum PacketParsingError {
    InvalidVersion(u8),
    IncorrectLength,
}

impl Display for PacketParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidVersion(version) => {
                f.write_fmt(format_args!("Invalid version {}", version))
            }
            Self::IncorrectLength => f.write_str("Incorrect packet length"),
        }
    }
}

impl std::error::Error for PacketParsingError {}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NtpLeapIndicator {
    NoWarning,
    Leap61,
    Leap59,
    Unknown,
}

impl NtpLeapIndicator {
    // This function should only ever be called with 2 bit values
    // (in the least significant position)
    fn from_bits(bits: u8) -> NtpLeapIndicator {
        match bits {
            0 => NtpLeapIndicator::NoWarning,
            1 => NtpLeapIndicator::Leap61,
            2 => NtpLeapIndicator::Leap59,
            3 => NtpLeapIndicator::Unknown,
            // This function should only ever be called from the packet parser
            // with just two bits, so this really should be unreachable
            _ => unreachable!(),
        }
    }

    fn to_bits(self) -> u8 {
        match self {
            NtpLeapIndicator::NoWarning => 0,
            NtpLeapIndicator::Leap61 => 1,
            NtpLeapIndicator::Leap59 => 2,
            NtpLeapIndicator::Unknown => 3,
        }
    }

    pub fn is_synchronized(&self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NtpAssociationMode {
    Reserved,
    SymmetricActive,
    SymmetricPassive,
    Client,
    Server,
    Broadcast,
    Control,
    Private,
}

impl NtpAssociationMode {
    // This function should only ever be called with 3 bit values
    // (in the least significant position)
    fn from_bits(bits: u8) -> NtpAssociationMode {
        match bits {
            0 => NtpAssociationMode::Reserved,
            1 => NtpAssociationMode::SymmetricActive,
            2 => NtpAssociationMode::SymmetricPassive,
            3 => NtpAssociationMode::Client,
            4 => NtpAssociationMode::Server,
            5 => NtpAssociationMode::Broadcast,
            6 => NtpAssociationMode::Control,
            7 => NtpAssociationMode::Private,
            // This function should only ever be called from the packet parser
            // with just three bits, so this really should be unreachable
            _ => unreachable!(),
        }
    }

    fn to_bits(self) -> u8 {
        match self {
            NtpAssociationMode::Reserved => 0,
            NtpAssociationMode::SymmetricActive => 1,
            NtpAssociationMode::SymmetricPassive => 2,
            NtpAssociationMode::Client => 3,
            NtpAssociationMode::Server => 4,
            NtpAssociationMode::Broadcast => 5,
            NtpAssociationMode::Control => 6,
            NtpAssociationMode::Private => 7,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpPacket<'a> {
    header: NtpHeader,
    efdata: ExtensionFieldData<'a>,
    mac: Option<Mac<'a>>,
}

#[derive(Clone, PartialEq, Eq)]
pub enum ExtensionField<'a> {
    UniqueIdentifier(Cow<'a, [u8]>),
    NtsCookie(Cow<'a, [u8]>),
    NtsCookiePlaceholder { body_length: u16 },
    NtsEncryptedField { plaintext: Cow<'a, [u8]> },

    Unknown { typeid: u16, data: Cow<'a, [u8]> },
}

impl<'a> std::fmt::Debug for ExtensionField<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UniqueIdentifier(arg0) => f.debug_tuple("UniqueIdentifier").field(arg0).finish(),
            Self::NtsCookie(arg0) => f.debug_tuple("NtsCookie").field(arg0).finish(),
            Self::NtsCookiePlaceholder { body_length } => f
                .debug_struct("NtsCookiePlaceholder")
                .field("body_length", body_length)
                .finish(),
            Self::NtsEncryptedField { plaintext } => f
                .debug_struct("NtsEncryptedField")
                .field("plaintext", plaintext)
                .finish(),
            Self::Unknown { typeid, data } => f
                .debug_struct("Unknown")
                .field("typeid", typeid)
                .field("length", &data.len())
                .field("data", data)
                .finish(),
        }
    }
}

pub const fn next_multiple_of(lhs: usize, rhs: usize) -> usize {
    match lhs % rhs {
        0 => lhs,
        r => lhs + (rhs - r),
    }
}

impl<'a> ExtensionField<'a> {
    const MINIMUM_SIZE: usize = 16;

    fn into_owned(self) -> ExtensionField<'static> {
        use ExtensionField::*;

        match self {
            Unknown { typeid, data } => Unknown {
                typeid,
                data: Cow::Owned(data.into_owned()),
            },
            UniqueIdentifier(data) => UniqueIdentifier(Cow::Owned(data.into_owned())),
            NtsCookie(data) => NtsCookie(Cow::Owned(data.into_owned())),
            NtsCookiePlaceholder { body_length } => NtsCookiePlaceholder { body_length },
            NtsEncryptedField { plaintext } => NtsEncryptedField {
                plaintext: Cow::Owned(plaintext.into_owned()),
            },
        }
    }

    pub fn key_exchange_signature() -> Self {
        // the real plaintext is the packet up to the start of this extension field
        // it is inserted implicitly by the encoder
        ExtensionField::NtsEncryptedField {
            plaintext: [].as_slice().into(),
        }
    }

    fn encode_unique_identifier<W: std::io::Write>(
        w: &mut W,
        identifier: &[u8],
    ) -> std::io::Result<()> {
        let padding = [0; 4];

        w.write_all(&0x0104u16.to_be_bytes())?;
        w.write_all(&(4 + identifier.len() as u16).to_be_bytes())?;
        w.write_all(identifier)?;

        let padding_bytes = next_multiple_of(identifier.len(), 4) - identifier.len();
        w.write_all(&padding[..padding_bytes])?;

        Ok(())
    }

    fn encode_nts_cookie<W: std::io::Write>(w: &mut W, cookie: &[u8]) -> std::io::Result<()> {
        let padding = [0; 4];

        w.write_all(&0x0204u16.to_be_bytes())?;
        w.write_all(&(4 + cookie.len() as u16).to_be_bytes())?;
        w.write_all(cookie)?;

        let padding_bytes = next_multiple_of(cookie.len(), 4) - cookie.len();
        w.write_all(&padding[..padding_bytes])?;

        Ok(())
    }

    fn encode_nts_cookie_request_extra<W: std::io::Write>(
        w: &mut W,
        cookie: &[u8],
        extra: u8,
    ) -> std::io::Result<()> {
        let padding = [0; 4];

        Self::encode_nts_cookie(w, cookie)?;

        let body_length: u16 = cookie.len() as u16;
        for _ in 0..extra {
            w.write_all(&0x0304u16.to_be_bytes())?;
            w.write_all(&(4 + body_length).to_be_bytes())?;

            let zeros = [0u8; 100];
            let mut remaining = next_multiple_of(body_length as usize, 4);
            while remaining > 0 {
                let n = usize::min(zeros.len(), remaining);
                w.write_all(&zeros[..n])?;
                remaining -= n;
            }
        }

        Ok(())
    }

    fn encode_encryped(
        w: &mut Cursor<&mut Vec<u8>>,
        cipher: &Cipher,
        nonce: &Nonce,
    ) -> std::io::Result<()> {
        let padding = [0; 4];

        let current_position = w.position();

        let packet_so_far = &w.get_ref()[..current_position as usize];

        let payload = Payload {
            msg: b"",
            aad: packet_so_far,
        };

        let ct = cipher.encrypt(nonce, payload).unwrap();

        w.write_all(&0x0404u16.to_be_bytes())?;

        // NOTE: these are NOT rounded up to a number of words
        let nonce_octet_count = nonce.len();
        let ct_octet_count = ct.len();

        // + 8 for the extension field header (4 bytes) and nonce/cypher text length (2 bytes each)
        let signature_octet_count = 8 + next_multiple_of(nonce_octet_count + ct_octet_count, 4);

        w.write_all(&(signature_octet_count as u16).to_be_bytes())?;
        w.write_all(&(nonce_octet_count as u16).to_be_bytes())?;
        w.write_all(&(ct_octet_count as u16).to_be_bytes())?;

        w.write_all(nonce)?;
        let padding_bytes = next_multiple_of(nonce.len(), 4) - nonce.len();
        w.write_all(&padding[..padding_bytes])?;

        w.write_all(ct.as_slice())?;
        let padding_bytes = next_multiple_of(ct.len(), 4) - ct.len();
        w.write_all(&padding[..padding_bytes])?;

        Ok(())
    }

    pub fn serialize(
        &self,
        w: &mut Cursor<&mut [u8]>,
        cipher: &Cipher,
        nonce: &Nonce,
    ) -> std::io::Result<()> {
        let padding = [0; 4];

        match self {
            ExtensionField::UniqueIdentifier(string) => {
                w.write_all(&0x0104u16.to_be_bytes())?;
                w.write_all(&(4 + string.len() as u16).to_be_bytes())?;
                w.write_all(string)?;

                let padding_bytes = next_multiple_of(string.len(), 4) - string.len();
                w.write_all(&padding[..padding_bytes])?;
            }
            ExtensionField::NtsCookie(cookie) => {
                w.write_all(&0x0204u16.to_be_bytes())?;
                w.write_all(&(4 + cookie.len() as u16).to_be_bytes())?;
                w.write_all(cookie)?;

                let padding_bytes = next_multiple_of(cookie.len(), 4) - cookie.len();
                w.write_all(&padding[..padding_bytes])?;
            }
            ExtensionField::NtsCookiePlaceholder { body_length } => {
                w.write_all(&0x0304u16.to_be_bytes())?;
                w.write_all(&(4 + body_length).to_be_bytes())?;

                let zeros = [0u8; 100];
                let mut remaining = next_multiple_of(*body_length as usize, 4);
                while remaining > 0 {
                    let n = usize::min(zeros.len(), remaining);
                    w.write_all(&zeros[..n])?;
                    remaining -= n;
                }
            }
            ExtensionField::NtsEncryptedField { plaintext: _ } => {
                let current_position = w.position();

                let packet_so_far = &w.get_ref()[..current_position as usize];

                let payload = Payload {
                    msg: b"",
                    aad: packet_so_far,
                };

                let ct = cipher.encrypt(nonce, payload).unwrap();

                w.write_all(&0x0404u16.to_be_bytes())?;

                // NOTE: these are NOT rounded up to a number of words
                let nonce_octet_count = nonce.len();
                let ct_octet_count = ct.len();

                // + 8 for the extension field header (4 bytes) and nonce/cypher text length (2 bytes each)
                let signature_octet_count =
                    8 + next_multiple_of(nonce_octet_count + ct_octet_count, 4);

                w.write_all(&(signature_octet_count as u16).to_be_bytes())?;
                w.write_all(&(nonce_octet_count as u16).to_be_bytes())?;
                w.write_all(&(ct_octet_count as u16).to_be_bytes())?;

                w.write_all(nonce)?;
                let padding_bytes = next_multiple_of(nonce.len(), 4) - nonce.len();
                w.write_all(&padding[..padding_bytes])?;

                w.write_all(ct.as_slice())?;
                let padding_bytes = next_multiple_of(ct.len(), 4) - ct.len();
                w.write_all(&padding[..padding_bytes])?;
            }
            ExtensionField::Unknown { typeid, data } => {
                if data.len() > u16::MAX as usize {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        PacketParsingError::IncorrectLength,
                    ));
                }
                w.write_all(&typeid.to_be_bytes())?;
                w.write_all(&(4u16 + data.len() as u16).to_be_bytes())?;
                w.write_all(data)?;

                let padding_bytes = next_multiple_of(data.len(), 4) - data.len();
                w.write_all(&padding[..padding_bytes])?;
            }
        }

        Ok(())
    }

    pub fn deserialize(
        data: &'a [u8],
        cipher: &Cipher,
    ) -> Result<(ExtensionField<'a>, usize), PacketParsingError> {
        use PacketParsingError::IncorrectLength;

        if data.len() < 4 || data.len() % 4 != 0 {
            return Err(IncorrectLength);
        }

        let typeid = u16::from_be_bytes(data[0..2].try_into().unwrap());
        let ef_len = u16::from_be_bytes(data[2..4].try_into().unwrap()) as usize;
        if ef_len < Self::MINIMUM_SIZE {
            return Err(PacketParsingError::IncorrectLength);
        }

        let value = data.get(4..ef_len).ok_or(IncorrectLength)?;

        // check that the padding is all zeros. This is required for the fuzz tests to work
        let padding = &data[ef_len..next_multiple_of(ef_len, 4)];
        if padding.iter().any(|b| *b != 0) {
            return Err(PacketParsingError::IncorrectLength);
        }

        let field = match typeid {
            0x104 => {
                // The string MUST be at least 32 octets long
                if value.len() < 32 {
                    return Err(IncorrectLength);
                }

                ExtensionField::UniqueIdentifier(value[..].into())
            }
            0x204 => ExtensionField::NtsCookie(value[..].into()),
            0x304 => {
                if value.iter().any(|b| *b != 0) {
                    return Err(PacketParsingError::IncorrectLength);
                }

                ExtensionField::NtsCookiePlaceholder {
                    body_length: value.len() as u16,
                }
            }
            0x404 => {
                let nonce_length = u16::from_be_bytes(value[0..2].try_into().unwrap()) as usize;
                let ciphertext_length =
                    u16::from_be_bytes(value[2..4].try_into().unwrap()) as usize;

                if 4 + next_multiple_of(nonce_length, 4) + next_multiple_of(ciphertext_length, 4)
                    != next_multiple_of(value.len(), 4)
                {
                    return Err(PacketParsingError::IncorrectLength);
                }

                let ciphertext_start = 4 + next_multiple_of(nonce_length as usize, 4);

                let nonce = value.get(4..4 + nonce_length).ok_or(IncorrectLength)?;
                let nonce_padding = value
                    .get(4 + nonce_length..ciphertext_start)
                    .ok_or(IncorrectLength)?;

                if nonce_padding.iter().any(|b| *b != 0) {
                    return Err(PacketParsingError::IncorrectLength);
                }

                let ciphertext = value
                    .get(ciphertext_start..ciphertext_start + ciphertext_length)
                    .ok_or(IncorrectLength)?;

                let plaintext = match cipher.decrypt(Nonce::from_slice(nonce), ciphertext) {
                    Ok(plain) => plain,
                    Err(e) => panic!("decryption failed {e:?}"),
                };

                let ciphertext_padding = value
                    .get(ciphertext_start + ciphertext_length..)
                    .ok_or(IncorrectLength)?;

                if ciphertext_padding.iter().any(|b| *b != 0) {
                    return Err(PacketParsingError::IncorrectLength);
                }

                ExtensionField::NtsEncryptedField {
                    plaintext: plaintext.into(),
                }
            }
            _ => ExtensionField::Unknown {
                typeid,
                data: Cow::Borrowed(value),
            },
        };

        Ok((field, next_multiple_of(ef_len, 4)))
    }

    fn decode_unique_identifier(message: &'a [u8]) -> Result<Self, PacketParsingError> {
        // The string MUST be at least 32 octets long
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
                body_length: message.len() as u16,
            })
        }
    }

    fn decode_unknown(message: &'a [u8]) -> Result<Self, PacketParsingError> {
        Ok(ExtensionField::Unknown {
            typeid: 0, // TODO is it actually required that we keep this around?
            data: Cow::Borrowed(message),
        })
    }
}

struct WireEncryptedField<'a> {
    nonce: &'a Nonce,
    ciphertext: &'a [u8],
}

impl<'a> WireEncryptedField<'a> {
    fn from_message_bytes(message_bytes: &'a [u8]) -> Result<Self, PacketParsingError> {
        use PacketParsingError::*;

        let value = message_bytes;

        let nonce_length = u16::from_be_bytes(value[0..2].try_into().unwrap()) as usize;
        let ciphertext_length = u16::from_be_bytes(value[2..4].try_into().unwrap()) as usize;

        if 4 + next_multiple_of(nonce_length, 4) + next_multiple_of(ciphertext_length, 4)
            != next_multiple_of(value.len(), 4)
        {
            return Err(PacketParsingError::IncorrectLength);
        }

        let ciphertext_start = 4 + next_multiple_of(nonce_length as usize, 4);

        let nonce_bytes = value.get(4..4 + nonce_length).ok_or(IncorrectLength)?;
        let nonce_padding = value
            .get(4 + nonce_length..ciphertext_start)
            .ok_or(IncorrectLength)?;

        if nonce_padding.iter().any(|b| *b != 0) {
            return Err(PacketParsingError::IncorrectLength);
        }

        let ciphertext = value
            .get(ciphertext_start..ciphertext_start + ciphertext_length)
            .ok_or(IncorrectLength)?;

        Ok(Self {
            nonce: Nonce::from_slice(nonce_bytes),
            ciphertext,
        })
    }
}

#[derive(Debug)]
struct WireExtensionField<'a> {
    type_id: ExtensionFieldTypeId,
    // bytes of just the message: does not include the header or padding
    message_bytes: &'a [u8],
}

impl<'a> WireExtensionField<'a> {
    const MINIMUM_SIZE: usize = 16;

    fn wire_length(&self) -> usize {
        // type_id and extension_field_length + data + padding
        4 + next_multiple_of(self.message_bytes.len(), 4)
    }

    pub fn parse(data: &'a [u8]) -> Result<Self, PacketParsingError> {
        use PacketParsingError::IncorrectLength;

        if data.len() < 4 || data.len() % 4 != 0 {
            return Err(IncorrectLength);
        }

        let type_id = u16::from_be_bytes(data[0..2].try_into().unwrap());
        let field_length = u16::from_be_bytes(data[2..4].try_into().unwrap()) as usize;
        if field_length < Self::MINIMUM_SIZE {
            return Err(PacketParsingError::IncorrectLength);
        }

        let value = data.get(4..field_length).ok_or(IncorrectLength)?;

        // check that the padding is all zeros. This is required for the fuzz tests to work
        let padding = &data[field_length..next_multiple_of(field_length, 4)];
        if padding.iter().any(|b| *b != 0) {
            return Err(PacketParsingError::IncorrectLength);
        }

        Ok(Self {
            type_id: ExtensionFieldTypeId::from_type_id(type_id),
            message_bytes: value,
        })
    }
}

#[derive(Debug)]
#[repr(u16)]
enum ExtensionFieldTypeId {
    UniqueIdentifier = 0x104,
    NtsCookie = 0x204,
    NtsCookiePlaceholder = 0x304,
    NtsEncryptedField = 0x404,
    Unknown,
}

impl ExtensionFieldTypeId {
    fn from_type_id(type_id: u16) -> Self {
        match type_id {
            0x104 => Self::UniqueIdentifier,
            0x204 => Self::NtsCookie,
            0x304 => Self::NtsCookiePlaceholder,
            0x404 => Self::NtsEncryptedField,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ExtensionFieldData<'a> {
    authenticated: Vec<ExtensionField<'a>>,
    encrypted: Vec<ExtensionField<'a>>,
    trailing: Vec<ExtensionField<'a>>,
}

impl<'a> ExtensionFieldData<'a> {
    fn into_owned(self) -> ExtensionFieldData<'static> {
        let map_into_owned =
            |vec: Vec<ExtensionField>| vec.into_iter().map(ExtensionField::into_owned).collect();

        ExtensionFieldData {
            authenticated: map_into_owned(self.authenticated),
            encrypted: map_into_owned(self.encrypted),
            trailing: map_into_owned(self.trailing),
        }
    }

    fn serialize(
        &self,
        w: &mut Cursor<&mut [u8]>,
        cipher: &Cipher,
        nonce: &Nonce,
    ) -> std::io::Result<()> {
        let fields = [&self.authenticated, &self.encrypted, &self.trailing];

        for field in fields.into_iter().flatten() {
            field.serialize(w, cipher, nonce)?;
        }

        Ok(())
    }

    fn deserialize(
        data: &'a [u8],
        header_size: usize,
        cipher: &Cipher,
    ) -> Result<(Self, usize), PacketParsingError> {
        let mut offset = header_size;

        let mut this = Self::default();
        let mut encrypted_field = None;

        while data.len() - offset >= Mac::MAXIMUM_SIZE {
            type EF<'a> = ExtensionField<'a>;
            type TypeId = ExtensionFieldTypeId;

            let raw_ext_field = WireExtensionField::parse(&data[offset..])?;
            let message = raw_ext_field.message_bytes;

            let field = match raw_ext_field.type_id {
                TypeId::NtsEncryptedField => {
                    let packet_so_far = &data[..offset];
                    let field = WireEncryptedField::from_message_bytes(message)?;
                    encrypted_field = Some((field, packet_so_far));
                    offset += raw_ext_field.wire_length();
                    break;
                }
                TypeId::UniqueIdentifier => EF::decode_unique_identifier(message)?,
                TypeId::NtsCookie => EF::decode_nts_cookie(message)?,
                TypeId::NtsCookiePlaceholder => EF::decode_nts_cookie_placeholder(message)?,
                TypeId::Unknown => EF::decode_unknown(message)?,
            };

            this.authenticated.push(field);
            offset += raw_ext_field.wire_length();
        }

        if let Some((encrypted, packet_so_far)) = encrypted_field {
            let payload = Payload {
                msg: encrypted.ciphertext,
                aad: packet_so_far,
            };

            let plaintext = match cipher.decrypt(encrypted.nonce, payload) {
                Ok(plain) => plain,
                Err(e) => panic!("failed to decrypt: {e:?}"),
            };

            dbg!(plaintext.len());

            let mut offset = 0;
            while offset < plaintext.len() {
                type EF<'a> = ExtensionField<'a>;
                type TypeId = ExtensionFieldTypeId;

                let raw_ext_field = WireExtensionField::parse(&plaintext[offset..])?;
                let message = raw_ext_field.message_bytes;

                let field = match raw_ext_field.type_id {
                    TypeId::NtsEncryptedField => {
                        todo!("nested encrypted field should not happen")
                    }
                    TypeId::UniqueIdentifier => EF::decode_unique_identifier(message)?,
                    TypeId::NtsCookie => EF::decode_nts_cookie(message)?,
                    TypeId::NtsCookiePlaceholder => EF::decode_nts_cookie_placeholder(message)?,
                    TypeId::Unknown => EF::decode_unknown(message)?,
                };

                this.encrypted.push(field.into_owned());
                offset += raw_ext_field.wire_length();
            }
        }

        while data.len() - offset >= Mac::MAXIMUM_SIZE {
            type EF<'a> = ExtensionField<'a>;
            type TypeId = ExtensionFieldTypeId;

            let raw_ext_field = WireExtensionField::parse(&data[offset..])?;
            let message = raw_ext_field.message_bytes;

            let field = match raw_ext_field.type_id {
                TypeId::NtsEncryptedField => {
                    todo!("nested encrypted field should not happen")
                }
                TypeId::UniqueIdentifier => EF::decode_unique_identifier(message)?,
                TypeId::NtsCookie => EF::decode_nts_cookie(message)?,
                TypeId::NtsCookiePlaceholder => EF::decode_nts_cookie_placeholder(message)?,
                TypeId::Unknown => EF::decode_unknown(message)?,
            };

            this.trailing.push(field.into_owned());
            offset += raw_ext_field.wire_length();
        }

        Ok((this, offset))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mac<'a> {
    keyid: u32,
    mac: Cow<'a, [u8]>,
}

impl<'a> Mac<'a> {
    const MAXIMUM_SIZE: usize = 28;

    fn into_owned(self) -> Mac<'static> {
        Mac {
            keyid: self.keyid,
            mac: Cow::Owned(self.mac.into_owned()),
        }
    }

    fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&self.keyid.to_be_bytes())?;
        w.write_all(&self.mac)
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, PacketParsingError> {
        if data.len() < 4 || data.len() >= Self::MAXIMUM_SIZE {
            return Err(PacketParsingError::IncorrectLength);
        }

        Ok(Mac {
            keyid: u32::from_be_bytes(data[0..4].try_into().unwrap()),
            mac: Cow::Borrowed(&data[4..]),
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum NtpHeader {
    V3(NtpHeaderV3V4),
    V4(NtpHeaderV3V4),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct NtpHeaderV3V4 {
    leap: NtpLeapIndicator,
    mode: NtpAssociationMode,
    stratum: u8,
    poll: i8,
    precision: i8,
    root_delay: NtpDuration,
    root_dispersion: NtpDuration,
    reference_id: ReferenceId,
    reference_timestamp: NtpTimestamp,
    /// Time at the client when the request departed for the server
    origin_timestamp: NtpTimestamp,
    /// Time at the server when the request arrived from the client
    receive_timestamp: NtpTimestamp,
    /// Time at the server when the response left for the client
    transmit_timestamp: NtpTimestamp,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RequestIdentifier {
    expected_origin_timestamp: NtpTimestamp,
}

impl NtpHeaderV3V4 {
    const LENGTH: usize = 48;

    /// A new, empty NtpHeader
    fn new() -> Self {
        Self {
            leap: NtpLeapIndicator::NoWarning,
            mode: NtpAssociationMode::Client,
            stratum: 0,
            poll: 0,
            precision: 0,
            root_delay: NtpDuration::default(),
            root_dispersion: NtpDuration::default(),
            reference_id: ReferenceId::from_int(0),
            reference_timestamp: NtpTimestamp::default(),
            origin_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            transmit_timestamp: NtpTimestamp::default(),
        }
    }

    fn deserialize(data: &[u8]) -> Result<(Self, usize), PacketParsingError> {
        if data.len() < Self::LENGTH {
            return Err(PacketParsingError::IncorrectLength);
        }

        Ok((
            Self {
                leap: NtpLeapIndicator::from_bits((data[0] & 0xC0) >> 6),
                mode: NtpAssociationMode::from_bits(data[0] & 0x07),
                stratum: data[1],
                poll: data[2] as i8,
                precision: data[3] as i8,
                root_delay: NtpDuration::from_bits_short(data[4..8].try_into().unwrap()),
                root_dispersion: NtpDuration::from_bits_short(data[8..12].try_into().unwrap()),
                reference_id: ReferenceId::from_bytes(data[12..16].try_into().unwrap()),
                reference_timestamp: NtpTimestamp::from_bits(data[16..24].try_into().unwrap()),
                origin_timestamp: NtpTimestamp::from_bits(data[24..32].try_into().unwrap()),
                receive_timestamp: NtpTimestamp::from_bits(data[32..40].try_into().unwrap()),
                transmit_timestamp: NtpTimestamp::from_bits(data[40..48].try_into().unwrap()),
            },
            Self::LENGTH,
        ))
    }

    fn serialize<W: std::io::Write>(&self, w: &mut W, version: u8) -> std::io::Result<()> {
        w.write_all(&[(self.leap.to_bits() << 6) | (version << 3) | self.mode.to_bits()])?;
        w.write_all(&[self.stratum, self.poll as u8, self.precision as u8])?;
        w.write_all(&self.root_delay.to_bits_short())?;
        w.write_all(&self.root_dispersion.to_bits_short())?;
        w.write_all(&self.reference_id.to_bytes())?;
        w.write_all(&self.reference_timestamp.to_bits())?;
        w.write_all(&self.origin_timestamp.to_bits())?;
        w.write_all(&self.receive_timestamp.to_bits())?;
        w.write_all(&self.transmit_timestamp.to_bits())?;
        Ok(())
    }

    fn poll_message(poll_interval: PollInterval) -> (Self, RequestIdentifier) {
        let mut packet = Self::new();
        let poll_interval = poll_interval;
        packet.poll = poll_interval.as_log();
        packet.mode = NtpAssociationMode::Client;

        // In order to increase the entropy of the transmit timestamp
        // it is just a randomly generated timestamp.
        // We then expect to get it back identically from the remote
        // in the origin field.
        let transmit_timestamp = thread_rng().gen();
        packet.transmit_timestamp = transmit_timestamp;

        (
            packet,
            RequestIdentifier {
                expected_origin_timestamp: transmit_timestamp,
            },
        )
    }

    fn timestamp_response<C: NtpClock>(
        system: &SystemSnapshot,
        input: Self,
        recv_timestamp: NtpTimestamp,
        clock: &C,
    ) -> Self {
        Self {
            mode: NtpAssociationMode::Server,
            stratum: system.stratum,
            origin_timestamp: input.transmit_timestamp,
            receive_timestamp: recv_timestamp,
            reference_id: system.reference_id,
            poll: input.poll,
            precision: system.time_snapshot.precision.log2(),
            root_delay: system.time_snapshot.root_delay,
            root_dispersion: system.time_snapshot.root_dispersion,
            // Timestamp must be last to make it as accurate as possible.
            transmit_timestamp: clock.now().expect("Failed to read time"),
            ..Self::new()
        }
    }

    fn rate_limit_response(packet_from_client: Self) -> Self {
        Self {
            mode: NtpAssociationMode::Server,
            stratum: 0, // indicates a kiss code
            reference_id: ReferenceId::KISS_RATE,
            origin_timestamp: packet_from_client.transmit_timestamp,
            ..Self::new()
        }
    }

    fn deny_response(packet_from_client: Self) -> Self {
        Self {
            mode: NtpAssociationMode::Server,
            stratum: 0, // indicates a kiss code
            reference_id: ReferenceId::KISS_DENY,
            origin_timestamp: packet_from_client.transmit_timestamp,
            ..Self::new()
        }
    }
}

impl<'a> NtpPacket<'a> {
    pub fn into_owned(self) -> NtpPacket<'static> {
        NtpPacket::<'static> {
            header: self.header,
            efdata: self.efdata.into_owned(),
            mac: self.mac.map(|v| v.into_owned()),
        }
    }

    pub fn deserialize_without_decryption(data: &'a [u8]) -> Result<Self, PacketParsingError> {
        use aes_siv::{aead::KeyInit, Key};

        let cipher = Cipher::new(Key::<Cipher>::from_slice([0; 64].as_slice()));

        Self::deserialize(data, &cipher)
    }

    pub fn deserialize(data: &'a [u8], cipher: &Cipher) -> Result<Self, PacketParsingError> {
        if data.is_empty() {
            return Err(PacketParsingError::IncorrectLength);
        }

        let version = (data[0] & 0x38) >> 3;

        println!("{:08b}", data[0]);
        dbg!(data[0], version);

        match version {
            3 => {
                let (header, header_size) = NtpHeaderV3V4::deserialize(data)?;
                let mac = if header_size != data.len() {
                    Some(Mac::deserialize(&data[header_size..])?)
                } else {
                    None
                };
                Ok(NtpPacket {
                    header: NtpHeader::V3(header),
                    efdata: ExtensionFieldData::default(),
                    mac,
                })
            }
            4 => {
                let (header, header_size) = NtpHeaderV3V4::deserialize(data)?;
                let (efdata, header_plus_fields_len) =
                    dbg!(ExtensionFieldData::deserialize(data, header_size, cipher))?;

                let mac = if header_plus_fields_len != data.len() {
                    Some(dbg!(Mac::deserialize(&data[header_plus_fields_len..]))?)
                } else {
                    None
                };

                Ok(NtpPacket {
                    header: NtpHeader::V4(header),
                    efdata,
                    mac,
                })
            }
            _ => Err(PacketParsingError::InvalidVersion(version)),
        }
    }

    #[cfg(test)]
    fn serialize_without_encryption_vec(&self) -> std::io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; 1024];
        let mut cursor = Cursor::new(buffer.as_mut_slice());

        self.serialize_without_encryption(&mut cursor)?;

        let length = cursor.position() as usize;
        let buffer = cursor.into_inner()[..length].to_vec();

        Ok(buffer)
    }

    pub fn serialize_without_encryption(&self, w: &mut Cursor<&mut [u8]>) -> std::io::Result<()> {
        use aes_siv::{aead::KeyInit, Key};

        let cipher = Cipher::new(Key::<Cipher>::from_slice([0; 64].as_slice()));

        self.serialize(w, &cipher, Nonce::from_slice(&[0u8; 16]))
    }

    pub fn serialize(
        &self,
        w: &mut Cursor<&mut [u8]>,
        cipher: &Cipher,
        nonce: &Nonce,
    ) -> std::io::Result<()> {
        match self.header {
            NtpHeader::V3(header) => header.serialize(w, 3)?,
            NtpHeader::V4(header) => header.serialize(w, 4)?,
        };

        match self.header {
            NtpHeader::V3(_) => { /* v3 does not support NTS, so we ignore extension fields */ }
            NtpHeader::V4(_) => self.efdata.serialize(w, cipher, nonce)?,
        }

        if let Some(ref mac) = self.mac {
            mac.serialize(w)?;
        }

        Ok(())
    }

    pub fn serialize_nts_poll_message(
        output: &mut Vec<u8>,
        identifier: &[u8],
        cookie: &[u8],
        cipher: Cipher,
        nonce: &Nonce,
        poll_interval: PollInterval,
    ) -> std::io::Result<RequestIdentifier> {
        let (header, id) = Self::serialize_poll_message(poll_interval)?;

        output.extend(&header);

        ExtensionField::encode_unique_identifier(output, identifier).unwrap();
        ExtensionField::encode_nts_cookie_request_extra(output, cookie, 1).unwrap();

        let start_position = output.len();
        let mut cursor = Cursor::new(output);
        cursor.set_position(start_position as u64);

        ExtensionField::encode_encryped(&mut cursor, &cipher, nonce).unwrap();

        Ok(id)
    }

    pub fn serialize_poll_message(
        poll_interval: PollInterval,
    ) -> std::io::Result<([u8; 48], RequestIdentifier)> {
        let (header, id) = NtpHeaderV3V4::poll_message(poll_interval);

        let mut output = [0; 48];
        let mut w = Cursor::new(output.as_mut_slice());
        header.serialize(&mut w, 4)?;

        Ok((output, id))
    }

    pub fn poll_message(poll_interval: PollInterval) -> (Self, RequestIdentifier) {
        let (header, id) = NtpHeaderV3V4::poll_message(poll_interval);
        (
            NtpPacket {
                header: NtpHeader::V4(header),
                efdata: Default::default(),
                mac: None,
            },
            id,
        )
    }

    pub fn timestamp_response<C: NtpClock>(
        system: &SystemSnapshot,
        input: Self,
        recv_timestamp: NtpTimestamp,
        clock: &C,
    ) -> Self {
        match input.header {
            NtpHeader::V3(header) => NtpPacket {
                header: NtpHeader::V3(NtpHeaderV3V4::timestamp_response(
                    system,
                    header,
                    recv_timestamp,
                    clock,
                )),
                efdata: Default::default(),
                mac: None,
            },
            NtpHeader::V4(header) => NtpPacket {
                header: NtpHeader::V4(NtpHeaderV3V4::timestamp_response(
                    system,
                    header,
                    recv_timestamp,
                    clock,
                )),
                efdata: Default::default(),
                mac: None,
            },
        }
    }

    pub fn rate_limit_response(packet_from_client: Self) -> Self {
        match packet_from_client.header {
            NtpHeader::V3(header) => NtpPacket {
                header: NtpHeader::V3(NtpHeaderV3V4::rate_limit_response(header)),
                efdata: Default::default(),
                mac: None,
            },
            NtpHeader::V4(header) => NtpPacket {
                header: NtpHeader::V4(NtpHeaderV3V4::rate_limit_response(header)),
                efdata: Default::default(),
                mac: None,
            },
        }
    }

    pub fn deny_response(packet_from_client: Self) -> Self {
        match packet_from_client.header {
            NtpHeader::V3(header) => NtpPacket {
                header: NtpHeader::V3(NtpHeaderV3V4::deny_response(header)),
                efdata: Default::default(),
                mac: None,
            },
            NtpHeader::V4(header) => NtpPacket {
                header: NtpHeader::V4(NtpHeaderV3V4::deny_response(header)),
                efdata: Default::default(),
                mac: None,
            },
        }
    }
}

impl<'a> NtpPacket<'a> {
    pub fn leap(&self) -> NtpLeapIndicator {
        match self.header {
            NtpHeader::V3(header) => header.leap,
            NtpHeader::V4(header) => header.leap,
        }
    }

    pub fn mode(&self) -> NtpAssociationMode {
        match self.header {
            NtpHeader::V3(header) => header.mode,
            NtpHeader::V4(header) => header.mode,
        }
    }

    pub fn stratum(&self) -> u8 {
        match self.header {
            NtpHeader::V3(header) => header.stratum,
            NtpHeader::V4(header) => header.stratum,
        }
    }

    pub fn precision(&self) -> i8 {
        match self.header {
            NtpHeader::V3(header) => header.precision,
            NtpHeader::V4(header) => header.precision,
        }
    }

    pub fn root_delay(&self) -> NtpDuration {
        match self.header {
            NtpHeader::V3(header) => header.root_delay,
            NtpHeader::V4(header) => header.root_delay,
        }
    }

    pub fn root_dispersion(&self) -> NtpDuration {
        match self.header {
            NtpHeader::V3(header) => header.root_dispersion,
            NtpHeader::V4(header) => header.root_dispersion,
        }
    }

    pub fn receive_timestamp(&self) -> NtpTimestamp {
        match self.header {
            NtpHeader::V3(header) => header.receive_timestamp,
            NtpHeader::V4(header) => header.receive_timestamp,
        }
    }

    pub fn transmit_timestamp(&self) -> NtpTimestamp {
        match self.header {
            NtpHeader::V3(header) => header.transmit_timestamp,
            NtpHeader::V4(header) => header.transmit_timestamp,
        }
    }

    pub fn reference_id(&self) -> ReferenceId {
        match self.header {
            NtpHeader::V3(header) => header.reference_id,
            NtpHeader::V4(header) => header.reference_id,
        }
    }

    pub fn is_kiss(&self) -> bool {
        match self.header {
            NtpHeader::V3(header) => header.stratum == 0,
            NtpHeader::V4(header) => header.stratum == 0,
        }
    }

    pub fn is_kiss_deny(&self) -> bool {
        self.is_kiss() && self.reference_id().is_deny()
    }

    pub fn is_kiss_rate(&self) -> bool {
        self.is_kiss() && self.reference_id().is_rate()
    }

    pub fn is_kiss_rstr(&self) -> bool {
        self.is_kiss() && self.reference_id().is_rstr()
    }

    pub fn is_kiss_ntsn(&self) -> bool {
        self.is_kiss() && self.reference_id().is_ntsn()
    }

    pub fn valid_server_response(&self, identifier: RequestIdentifier) -> bool {
        match self.header {
            NtpHeader::V3(header) => {
                header.origin_timestamp == identifier.expected_origin_timestamp
            }
            NtpHeader::V4(header) => {
                header.origin_timestamp == identifier.expected_origin_timestamp
            }
        }
    }
}

#[cfg(any(test, feature = "fuzz", feature = "ext-test"))]
impl<'a> NtpPacket<'a> {
    pub fn test() -> Self {
        Self::default()
    }

    pub fn set_mode(&mut self, mode: NtpAssociationMode) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.mode = mode,
            NtpHeader::V4(ref mut header) => header.mode = mode,
        }
    }

    pub fn set_origin_timestamp(&mut self, timestamp: NtpTimestamp) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.origin_timestamp = timestamp,
            NtpHeader::V4(ref mut header) => header.origin_timestamp = timestamp,
        }
    }

    pub fn set_transmit_timestamp(&mut self, timestamp: NtpTimestamp) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.transmit_timestamp = timestamp,
            NtpHeader::V4(ref mut header) => header.transmit_timestamp = timestamp,
        }
    }

    pub fn set_receive_timestamp(&mut self, timestamp: NtpTimestamp) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.receive_timestamp = timestamp,
            NtpHeader::V4(ref mut header) => header.receive_timestamp = timestamp,
        }
    }

    pub fn set_precision(&mut self, precision: i8) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.precision = precision,
            NtpHeader::V4(ref mut header) => header.precision = precision,
        }
    }

    pub fn set_leap(&mut self, leap: NtpLeapIndicator) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.leap = leap,
            NtpHeader::V4(ref mut header) => header.leap = leap,
        }
    }

    pub fn set_stratum(&mut self, stratum: u8) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.stratum = stratum,
            NtpHeader::V4(ref mut header) => header.stratum = stratum,
        }
    }

    pub fn set_reference_id(&mut self, reference_id: ReferenceId) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.reference_id = reference_id,
            NtpHeader::V4(ref mut header) => header.reference_id = reference_id,
        }
    }

    pub fn set_root_delay(&mut self, root_delay: NtpDuration) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.root_delay = root_delay,
            NtpHeader::V4(ref mut header) => header.root_delay = root_delay,
        }
    }

    pub fn set_root_dispersion(&mut self, root_dispersion: NtpDuration) {
        match &mut self.header {
            NtpHeader::V3(ref mut header) => header.root_dispersion = root_dispersion,
            NtpHeader::V4(ref mut header) => header.root_dispersion = root_dispersion,
        }
    }
}

impl<'a> Default for NtpPacket<'a> {
    fn default() -> Self {
        Self {
            header: NtpHeader::V4(NtpHeaderV3V4::new()),
            efdata: Default::default(),
            mac: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn roundtrip_bitrep_leap() {
        for i in 0..4u8 {
            let a = NtpLeapIndicator::from_bits(i);
            let b = a.to_bits();
            let c = NtpLeapIndicator::from_bits(b);
            assert_eq!(i, b);
            assert_eq!(a, c);
        }
    }

    #[test]
    fn roundtrip_bitrep_mode() {
        for i in 0..8u8 {
            let a = NtpAssociationMode::from_bits(i);
            let b = a.to_bits();
            let c = NtpAssociationMode::from_bits(b);
            assert_eq!(i, b);
            assert_eq!(a, c);
        }
    }

    #[test]
    fn test_captured_client() {
        let packet = b"\x23\x02\x06\xe8\x00\x00\x03\xff\x00\x00\x03\x7d\x5e\xc6\x9f\x0f\xe5\xf6\x62\x98\x7b\x61\xb9\xaf\xe5\xf6\x63\x66\x7b\x64\x99\x5d\xe5\xf6\x63\x66\x81\x40\x55\x90\xe5\xf6\x63\xa8\x76\x1d\xde\x48";
        let reference = NtpPacket {
            header: NtpHeader::V4(NtpHeaderV3V4 {
                leap: NtpLeapIndicator::NoWarning,
                mode: NtpAssociationMode::Client,
                stratum: 2,
                poll: 6,
                precision: -24,
                root_delay: NtpDuration::from_fixed_int(1023 << 16),
                root_dispersion: NtpDuration::from_fixed_int(893 << 16),
                reference_id: ReferenceId::from_int(0x5ec69f0f),
                reference_timestamp: NtpTimestamp::from_fixed_int(0xe5f662987b61b9af),
                origin_timestamp: NtpTimestamp::from_fixed_int(0xe5f663667b64995d),
                receive_timestamp: NtpTimestamp::from_fixed_int(0xe5f6636681405590),
                transmit_timestamp: NtpTimestamp::from_fixed_int(0xe5f663a8761dde48),
            }),
            efdata: Default::default(),
            mac: None,
        };

        assert_eq!(
            reference,
            NtpPacket::deserialize_without_decryption(packet).unwrap()
        );
        match reference.serialize_without_encryption_vec() {
            Ok(buf) => assert_eq!(packet[..], buf[..]),
            Err(e) => panic!("{:?}", e),
        }

        let packet = b"\x1B\x02\x06\xe8\x00\x00\x03\xff\x00\x00\x03\x7d\x5e\xc6\x9f\x0f\xe5\xf6\x62\x98\x7b\x61\xb9\xaf\xe5\xf6\x63\x66\x7b\x64\x99\x5d\xe5\xf6\x63\x66\x81\x40\x55\x90\xe5\xf6\x63\xa8\x76\x1d\xde\x48";
        let reference = NtpPacket {
            header: NtpHeader::V3(NtpHeaderV3V4 {
                leap: NtpLeapIndicator::NoWarning,
                mode: NtpAssociationMode::Client,
                stratum: 2,
                poll: 6,
                precision: -24,
                root_delay: NtpDuration::from_fixed_int(1023 << 16),
                root_dispersion: NtpDuration::from_fixed_int(893 << 16),
                reference_id: ReferenceId::from_int(0x5ec69f0f),
                reference_timestamp: NtpTimestamp::from_fixed_int(0xe5f662987b61b9af),
                origin_timestamp: NtpTimestamp::from_fixed_int(0xe5f663667b64995d),
                receive_timestamp: NtpTimestamp::from_fixed_int(0xe5f6636681405590),
                transmit_timestamp: NtpTimestamp::from_fixed_int(0xe5f663a8761dde48),
            }),
            efdata: Default::default(),
            mac: None,
        };

        assert_eq!(
            reference,
            NtpPacket::deserialize_without_decryption(packet).unwrap()
        );
        match reference.serialize_without_encryption_vec() {
            Ok(buf) => assert_eq!(packet[..], buf[..]),
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    fn test_captured_server() {
        let packet = b"\x24\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        let reference = NtpPacket {
            header: NtpHeader::V4(NtpHeaderV3V4 {
                leap: NtpLeapIndicator::NoWarning,
                mode: NtpAssociationMode::Server,
                stratum: 2,
                poll: 6,
                precision: -23,
                root_delay: NtpDuration::from_fixed_int(566 << 16),
                root_dispersion: NtpDuration::from_fixed_int(951 << 16),
                reference_id: ReferenceId::from_int(0xc035676c),
                reference_timestamp: NtpTimestamp::from_fixed_int(0xe5f661fd6f165f03),
                origin_timestamp: NtpTimestamp::from_fixed_int(0xe5f663a87619ef40),
                receive_timestamp: NtpTimestamp::from_fixed_int(0xe5f663a8798c6581),
                transmit_timestamp: NtpTimestamp::from_fixed_int(0xe5f663a8798eae2b),
            }),
            efdata: Default::default(),
            mac: None,
        };

        assert_eq!(
            reference,
            NtpPacket::deserialize_without_decryption(packet).unwrap()
        );
        match reference.serialize_without_encryption_vec() {
            Ok(buf) => assert_eq!(packet[..], buf[..]),
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    fn test_version() {
        let packet = b"\x04\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize_without_decryption(packet).is_err());
        let packet = b"\x0B\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize_without_decryption(packet).is_err());
        let packet = b"\x14\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize_without_decryption(packet).is_err());
        let packet = b"\x2B\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize_without_decryption(packet).is_err());
        let packet = b"\x34\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize_without_decryption(packet).is_err());
        let packet = b"\x3B\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b";
        assert!(NtpPacket::deserialize_without_decryption(packet).is_err());
    }

    #[test]
    fn test_packed_flags() {
        let base = b"\x24\x02\x06\xe9\x00\x00\x02\x36\x00\x00\x03\xb7\xc0\x35\x67\x6c\xe5\xf6\x61\xfd\x6f\x16\x5f\x03\xe5\xf6\x63\xa8\x76\x19\xef\x40\xe5\xf6\x63\xa8\x79\x8c\x65\x81\xe5\xf6\x63\xa8\x79\x8e\xae\x2b".to_owned();
        let base_structured = NtpPacket::deserialize_without_decryption(&base).unwrap();

        for leap_type in 0..3 {
            for mode in 0..8 {
                let mut header = base_structured.clone();
                header.set_leap(NtpLeapIndicator::from_bits(leap_type));
                header.set_mode(NtpAssociationMode::from_bits(mode));

                let data = header.serialize_without_encryption_vec().unwrap();
                let copy = NtpPacket::deserialize_without_decryption(&data).unwrap();
                assert_eq!(header, copy);
            }
        }

        for i in 0..=0xFF {
            let mut packet = base;
            packet[0] = i;

            if let Ok(a) = NtpPacket::deserialize_without_decryption(&packet) {
                let b = a.serialize_without_encryption_vec().unwrap();
                assert_eq!(packet[..], b[..]);
            }
        }
    }
}
