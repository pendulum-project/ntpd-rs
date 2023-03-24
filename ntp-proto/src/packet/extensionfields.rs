use std::borrow::Cow;
use std::f32::consts::E;
use std::ops::{Add, Rem, Sub};

use crate::DecodedServerCookie;

use super::crypto::Cipher;
use super::mac::Mac;

use super::{
    crypto::CipherProvider,
    error::ParsingError,
};

fn next_multiple_of<
    T: Copy + Eq + Add<T, Output = T> + Sub<T, Output = T> + Rem<T, Output = T> + Default,
>(
    lhs: T,
    rhs: T,
) -> T {
    if lhs % rhs == lhs - lhs {
        lhs
    } else {
        lhs + (rhs - (lhs % rhs))
    }
}

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

impl<'a> ExtensionField<'a> {
    const BARE_MINIMUM_SIZE: usize = 4;
    const V4_UNENCRYPTED_MINIMUM_SIZE: usize = 4;

    pub fn deserialize(header: ExtensionFieldHeader, data: &'a [u8]) -> Self {
        match header.ftype {
            ExtensionFieldTypeId::UniqueIdentifier => {
                ExtensionField::UniqueIdentifier(Cow::Borrowed(data))
            }
            ExtensionFieldTypeId::NtsCookie => ExtensionField::NtsCookie(Cow::Borrowed(data)),
            ExtensionFieldTypeId::NtsCookiePlaceholder => ExtensionField::NtsCookiePlaceholder {
                cookie_length: header.length - 4,
            },
            ExtensionFieldTypeId::NtsEncryptedField => ExtensionField::Unknown {
                type_id: header.ftype.to_type_id(),
                data: Cow::Borrowed(data),
            },
            ExtensionFieldTypeId::Unknown { type_id } => ExtensionField::Unknown {
                type_id,
                data: Cow::Borrowed(data),
            },
        }
    }

    fn encode_framing<W: std::io::Write>(
        w: &mut W,
        ef_id: ExtensionFieldTypeId,
        data_length: usize,
        minimum_size: usize,
    ) -> std::io::Result<()> {
        if data_length.max(minimum_size) > u16::MAX as usize - 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Extension field too long",
            ));
        }

        // u16 for the type_id, u16 for the length
        let header_width = 4;

        let actual_length =
            next_multiple_of(data_length.max(minimum_size) as u16 + header_width, 4);
        w.write_all(&ef_id.to_type_id().to_be_bytes())?;
        w.write_all(&actual_length.to_be_bytes())
    }

    fn encode_padding<W: std::io::Write>(
        w: &mut W,
        data_length: usize,
        minimum_size: usize,
    ) -> std::io::Result<()> {
        let target_length = next_multiple_of(data_length.max(minimum_size), 4);
        Self::write_zeros(w, target_length - data_length)
    }

    fn write_zeros(w: &mut impl std::io::Write, n: usize) -> std::io::Result<()> {
        let mut remaining = n;
        let padding_bytes = [0_u8; 32];
        while remaining > 0 {
            let added = usize::min(remaining as usize, padding_bytes.len());
            w.write_all(&padding_bytes[..added])?;

            remaining -= added;
        }

        Ok(())
    }

    pub fn serialize<W: std::io::Write>(&self, w: &mut W, minimum_size: usize) -> std::io::Result<()> {
        match self {
            ExtensionField::UniqueIdentifier(data) => {
                Self::encode_framing(w, ExtensionFieldTypeId::UniqueIdentifier, data.len(), minimum_size)?;
                w.write_all(&data)?;
                Self::encode_padding(w, data.len(), minimum_size)?;
                Ok(())
            },
            ExtensionField::NtsCookie(data) => {
                Self::encode_framing(w, ExtensionFieldTypeId::NtsCookie, data.len(), minimum_size)?;
                w.write_all(&data)?;
                Self::encode_padding(w, data.len(), minimum_size)?;
                Ok(())
            },
            ExtensionField::NtsCookiePlaceholder { cookie_length } => {
                Self::encode_framing(w, ExtensionFieldTypeId::NtsCookie, *cookie_length as _, minimum_size)?;
                Self::write_zeros(w, *cookie_length as _);
                Self::encode_padding(w, *cookie_length as _, minimum_size)?;
                Ok(())
            },
            ExtensionField::InvalidNtsEncryptedField => {
                panic!("Shouldn't be trying to serialize invalid fields");
            },
            ExtensionField::Unknown { type_id, data } => {
                Self::encode_framing(w, ExtensionFieldTypeId::Unknown { type_id: *type_id }, data.len(), minimum_size)?;
                w.write_all(&data)?;
                Self::encode_padding(w, data.len(), minimum_size)?;
                Ok(())
            },
        }
    }
}

struct ExtensionFieldHeader {
    ftype: ExtensionFieldTypeId,
    length: u16,
}

impl ExtensionFieldHeader {
    fn deserialize(data: &[u8]) -> Result<Self, ParsingError<std::convert::Infallible>> {
        if data.len() < 4 {
            Err(ParsingError::IncorrectLength)
        } else {
            Ok(ExtensionFieldHeader {
                ftype: ExtensionFieldTypeId::from_type_id(u16::from_be_bytes(
                    data[0..2].try_into().unwrap(),
                )),
                length: u16::from_be_bytes(data[2..4].try_into().unwrap()),
            })
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct ExtensionFieldData<'a> {
    authenticated: &'a [u8],
    encrypted: &'a [u8],
    untrusted: &'a [u8],
}

impl<'a> ExtensionFieldData<'a> {
    pub(super) fn deserialize(
        data: &'a mut [u8],
        header_size: usize,
        cipher: &impl CipherProvider,
    ) -> Result<
        (Self, &'a [u8], Option<DecodedServerCookie>),
        ParsingError<(ExtensionFieldData<'a>, &'a [u8])>,
    > {
        let mut offset = header_size;
        let mut untrusted = header_size..header_size;
        let mut encrypted = header_size..header_size;
        let mut authenticated = header_size..header_size;

        let mut has_invalid_nts = false;

        while let Ok(header) = ExtensionFieldHeader::deserialize(data) {
            if data.len() - offset <= Mac::MAXIMUM_SIZE {
                break;
            }

            if (header.length as usize) < ExtensionField::V4_UNENCRYPTED_MINIMUM_SIZE
                || (header.length as usize) > data.len() - offset
            {
                return Err(ParsingError::IncorrectLength);
            }

            match header.ftype {
                ExtensionFieldTypeId::NtsEncryptedField => {
                    if data.len() - offset < 8 || encrypted != (header_size..header_size) {
                        offset += header.length as usize;
                        untrusted.end = offset;
                        has_invalid_nts = true;
                        continue;
                    }

                    let nonce_length =
                        u16::from_be_bytes(data[offset + 4..offset + 6].try_into().unwrap())
                            as usize;
                    let ciphertext_length =
                        u16::from_be_bytes(data[offset + 6..offset + 8].try_into().unwrap())
                            as usize;

                    if 4 + next_multiple_of(nonce_length, 4)
                        + next_multiple_of(ciphertext_length, 4)
                        > (header.length as usize)
                    {
                        offset += header.length as usize;
                        untrusted.end = offset;
                        has_invalid_nts = true;
                        continue;
                    }

                    let (stable, mutable) =
                        data.split_at_mut(offset + 4 + next_multiple_of(nonce_length, 4));

                    let cipher = match cipher.get(ExtensionFieldIterator {
                        buffer: &stable[untrusted.clone()],
                    }) {
                        Some(cipher) => cipher,
                        None => {
                            offset += header.length as usize;
                            untrusted.end = offset;
                            has_invalid_nts = true;
                            continue;
                        }
                    };

                    let plaintext_len = match cipher.as_ref().decrypt_in_place(
                        &stable[offset + 8..offset + 8 + nonce_length],
                        &mut mutable[..ciphertext_length],
                        &stable[..offset],
                    ) {
                        Ok(n) => n,
                        Err(_) => {
                            offset += header.length as usize;
                            untrusted.end = offset;
                            has_invalid_nts = true;
                            continue;
                        }
                    };

                    let mut encrypted_offset = offset + 4 + next_multiple_of(nonce_length, 4);
                    let encrypted_end = encrypted_offset + plaintext_len;
                    encrypted.start = encrypted_offset;
                    encrypted.end = encrypted_offset;
                    while let Ok(inner_header) =
                        ExtensionFieldHeader::deserialize(&data[encrypted_offset..encrypted_end])
                    {
                        if encrypted_end - encrypted_offset < ExtensionField::BARE_MINIMUM_SIZE
                            || encrypted_end - encrypted_offset < (inner_header.length as usize)
                        {
                            break; // error is handled below
                        }

                        encrypted_offset += inner_header.length as usize;
                        encrypted.end = encrypted_offset;
                    }

                    if encrypted_end != encrypted_offset {
                        offset += header.length as usize;
                        untrusted.end = offset;
                        has_invalid_nts = true;
                        continue;
                    }

                    authenticated = untrusted.clone();
                    untrusted.start = offset + (header.length as usize);
                    untrusted.end = untrusted.start;
                }
                _ => {
                    offset += header.length as usize;
                    untrusted.end = offset;
                }
            }
        }

        let size = untrusted.end;

        if !has_invalid_nts {
            Ok((
                ExtensionFieldData {
                    authenticated: &data[authenticated],
                    encrypted: &data[encrypted],
                    untrusted: &data[untrusted],
                },
                &data[size..],
                None,
            ))
        } else {
            Err(ParsingError::DecryptError((
                ExtensionFieldData {
                    authenticated: &data[authenticated],
                    encrypted: &data[encrypted],
                    untrusted: &data[untrusted],
                },
                &data[size..],
            )))
        }
    }

    pub fn authenticated(&self) -> impl Iterator<Item = ExtensionField<'a>> + 'a {
        ExtensionFieldIterator {
            buffer: self.authenticated,
        }
    }

    pub fn encrypted(&self) -> impl Iterator<Item = ExtensionField<'a>> + 'a {
        ExtensionFieldIterator {
            buffer: self.encrypted,
        }
    }

    pub fn untrusted(&self) -> impl Iterator<Item = ExtensionField<'a>> + 'a {
        ExtensionFieldIterator {
            buffer: self.untrusted,
        }
    }
}

struct ExtensionFieldIterator<'a> {
    buffer: &'a [u8],
}

impl<'a> Iterator for ExtensionFieldIterator<'a> {
    type Item = ExtensionField<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Ok(header) = ExtensionFieldHeader::deserialize(self.buffer) {
            let (head, tail) = self.buffer.split_at(header.length as _);
            self.buffer = tail;
            Some(ExtensionField::deserialize(header, &head[4..]))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
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
        ExtensionField::UniqueIdentifier(Cow::Owned((0..16).collect())).serialize(&mut w, 0).unwrap();

        assert_eq!(
            w,
            &[1, 4, 0, 20, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn test_nts_cookie() {
        let mut w = vec![];
        ExtensionField::NtsCookie(Cow::Owned((0..16).collect())).serialize(&mut w, 0).unwrap();

        assert_eq!(
            w,
            &[2, 4, 0, 20, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn test_nts_cookie_placeholder() {
        let mut w = vec![];
        ExtensionField::NtsCookiePlaceholder { cookie_length: 16 }.serialize(&mut w, 0).unwrap();

        assert_eq!(
            w,
            &[3, 4, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]
        );
    }

    #[test]
    fn test_unknown() {
        let data: Vec<_> = (0..16).collect();
        let mut w = vec![];
        ExtensionField::Unknown { type_id: 42, data: Cow::Owned((0..16).collect()) }.serialize(&mut w, 0);

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
