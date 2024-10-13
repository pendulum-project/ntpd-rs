use std::{
    io::{Read, Write},
    sync::Arc,
};

use aead::{generic_array::GenericArray, KeyInit};

use crate::{
    nts_record::AeadAlgorithm,
    packet::{
        AesSivCmac256, AesSivCmac512, Cipher, CipherHolder, CipherProvider, DecryptError,
        EncryptResult, ExtensionField,
    },
};

pub struct DecodedServerCookie {
    pub(crate) algorithm: AeadAlgorithm,
    pub s2c: Box<dyn Cipher>,
    pub c2s: Box<dyn Cipher>,
}

impl DecodedServerCookie {
    fn plaintext(&self) -> Vec<u8> {
        let mut plaintext = Vec::new();

        let algorithm_bytes = (self.algorithm as u16).to_be_bytes();
        plaintext.extend_from_slice(&algorithm_bytes);
        plaintext.extend_from_slice(self.s2c.key_bytes());
        plaintext.extend_from_slice(self.c2s.key_bytes());

        plaintext
    }
}

impl std::fmt::Debug for DecodedServerCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedServerCookie")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct KeySetProvider {
    current: Arc<KeySet>,
    history: usize,
}

impl KeySetProvider {
    /// Create a new keysetprovider that keeps history old
    /// keys around (so in total, history+1 keys are valid
    /// at any time)
    #[must_use]
    pub fn new(history: usize) -> Self {
        KeySetProvider {
            current: Arc::new(KeySet {
                keys: vec![AesSivCmac512::new(aes_siv::Aes256SivAead::generate_key(
                    rand::thread_rng(),
                ))],
                id_offset: 0,
                primary: 0,
            }),
            history,
        }
    }

    #[cfg(feature = "__internal-fuzz")]
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn dangerous_new_deterministic(history: usize) -> Self {
        KeySetProvider {
            current: Arc::new(KeySet {
                keys: vec![AesSivCmac512::new(
                    std::array::from_fn(|i| (i as u8)).into(),
                )],
                id_offset: 0,
                primary: 0,
            }),
            history,
        }
    }

    /// Rotate a new key in as primary, forgetting an old one if needed
    #[allow(clippy::cast_possible_truncation)]
    pub fn rotate(&mut self) {
        let next_key = AesSivCmac512::new(aes_siv::Aes256SivAead::generate_key(rand::thread_rng()));
        let mut keys = Vec::with_capacity((self.history + 1).min(self.current.keys.len() + 1));
        for key in &self.current.keys
            [self.current.keys.len().saturating_sub(self.history)..self.current.keys.len()]
        {
            // This is the rare case where we do really want to make a copy.
            keys.push(AesSivCmac512::new(GenericArray::clone_from_slice(
                key.key_bytes(),
            )));
        }
        keys.push(next_key);
        self.current = Arc::new(KeySet {
            id_offset: self
                .current
                .id_offset
                .wrapping_add(self.current.keys.len().saturating_sub(self.history) as u32),
            primary: keys.len() as u32 - 1,
            keys,
        });
    }

    /// # Panics
    ///
    /// Panics if `buf` can't be converted to system time.
    ///
    /// # Errors
    ///
    /// Errors if `len` is bigger or equal to `primary`.
    pub fn load(
        reader: &mut impl Read,
        history: usize,
    ) -> std::io::Result<(Self, std::time::SystemTime)> {
        let mut buf = [0; 64];
        reader.read_exact(&mut buf[0..20])?;

        let time = Self::convert_to_system_time(&buf[0..8])?;
        let id_offset = Self::convert_to_u32(&buf[8..12])?;
        let primary = Self::convert_to_u32(&buf[12..16])?;
        let len = Self::convert_to_u32(&buf[16..20])?;

        if primary >= len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Primary key must be less than length",
            ));
        }

        let mut keys = vec![];
        for _ in 0..len {
            reader.read_exact(&mut buf[0..64])?;
            keys.push(AesSivCmac512::new(buf.into()));
        }
        Ok((
            KeySetProvider {
                current: Arc::new(KeySet {
                    keys,
                    id_offset,
                    primary,
                }),
                history,
            },
            time,
        ))
    }

    /// # Panics
    ///
    /// Panics if we can't get the current time.
    ///
    /// # Errors
    ///
    /// Errors if we can't write to the sink.
    #[allow(clippy::cast_possible_truncation)]
    pub fn store(&self, writer: &mut impl Write) -> std::io::Result<()> {
        let time = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("Could not get current time");
        writer.write_all(&time.as_secs().to_be_bytes())?;
        writer.write_all(&self.current.id_offset.to_be_bytes())?;
        writer.write_all(&self.current.primary.to_be_bytes())?;
        writer.write_all(&(self.current.keys.len() as u32).to_be_bytes())?;
        for key in &self.current.keys {
            writer.write_all(key.key_bytes())?;
        }
        Ok(())
    }

    /// Get the current `KeySet`
    #[must_use]
    pub fn get(&self) -> Arc<KeySet> {
        self.current.clone()
    }

    fn convert_to_system_time(bytes: &[u8]) -> std::io::Result<std::time::SystemTime> {
        let time = u64::from_be_bytes(bytes.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid buffer for SystemTime",
            )
        })?);
        Ok(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(time))
    }

    fn convert_to_u32(bytes: &[u8]) -> std::io::Result<u32> {
        let value = u32::from_be_bytes(bytes.try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid buffer for u32")
        })?);
        Ok(value)
    }
}

pub struct KeySet {
    keys: Vec<AesSivCmac512>,
    id_offset: u32,
    primary: u32,
}

impl KeySet {
    #[cfg(feature = "__internal-fuzz")]
    #[must_use]
    pub fn encode_cookie_pub(&self, cookie: &DecodedServerCookie) -> Vec<u8> {
        self.encode_cookie(cookie)
    }

    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn encode_cookie(&self, cookie: &DecodedServerCookie) -> Vec<u8> {
        let mut output = cookie.plaintext();
        let plaintext_length = output.as_slice().len();

        // Add space for header (4 + 2 bytes), additional ciphertext
        // data from the cmac (16 bytes) and nonce (16 bytes).
        output.resize(output.len() + 2 + 4 + 16 + 16, 0);

        // And move plaintext to make space for header
        output.copy_within(0..plaintext_length, 6);
        let EncryptResult {
            nonce_length,
            ciphertext_length,
        } = self.keys[self.primary as usize]
            .encrypt(&mut output[6..], plaintext_length, &[])
            .expect("Failed to encrypt cookie");

        debug_assert_eq!(nonce_length, 16);
        debug_assert_eq!(plaintext_length + 16, ciphertext_length);

        output[0..4].copy_from_slice(&(self.primary.wrapping_add(self.id_offset)).to_be_bytes());
        output[4..6].copy_from_slice(&(ciphertext_length as u16).to_be_bytes());
        debug_assert_eq!(output.len(), 6 + nonce_length + ciphertext_length);
        output
    }

    #[cfg(feature = "__internal-fuzz")]
    #[allow(clippy::missing_errors_doc)]
    pub fn decode_cookie_pub(&self, cookie: &[u8]) -> Result<DecodedServerCookie, DecryptError> {
        self.decode_cookie(cookie)
    }

    pub(crate) fn decode_cookie(&self, cookie: &[u8]) -> Result<DecodedServerCookie, DecryptError> {
        // we need at least an id, cipher text length and nonce for this message to be valid
        if cookie.len() < 4 + 2 + 16 {
            return Err(DecryptError);
        }

        let id = u32::from_be_bytes(cookie[0..4].try_into().unwrap());
        let id = id.wrapping_sub(self.id_offset) as usize;
        let key = self.keys.get(id).ok_or(DecryptError)?;

        let cipher_text_length = u16::from_be_bytes([cookie[4], cookie[5]]) as usize;

        let nonce = &cookie[6..22];
        let ciphertext = cookie[22..].get(..cipher_text_length).ok_or(DecryptError)?;
        let plaintext = key.decrypt(nonce, ciphertext, &[])?;

        let [b0, b1, ref key_bytes @ ..] = plaintext[..] else {
            return Err(DecryptError);
        };

        let algorithm =
            AeadAlgorithm::try_deserialize(u16::from_be_bytes([b0, b1])).ok_or(DecryptError)?;

        Ok(match algorithm {
            AeadAlgorithm::AeadAesSivCmac256 => {
                const KEY_WIDTH: usize = 32;

                if key_bytes.len() != 2 * KEY_WIDTH {
                    return Err(DecryptError);
                }

                let (s2c, c2s) = key_bytes.split_at(KEY_WIDTH);

                DecodedServerCookie {
                    algorithm,
                    s2c: Box::new(AesSivCmac256::new(GenericArray::clone_from_slice(s2c))),
                    c2s: Box::new(AesSivCmac256::new(GenericArray::clone_from_slice(c2s))),
                }
            }
            AeadAlgorithm::AeadAesSivCmac512 => {
                const KEY_WIDTH: usize = 64;

                if key_bytes.len() != 2 * KEY_WIDTH {
                    return Err(DecryptError);
                }

                let (s2c, c2s) = key_bytes.split_at(KEY_WIDTH);

                DecodedServerCookie {
                    algorithm,
                    s2c: Box::new(AesSivCmac512::new(GenericArray::clone_from_slice(s2c))),
                    c2s: Box::new(AesSivCmac512::new(GenericArray::clone_from_slice(c2s))),
                }
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self {
            keys: vec![AesSivCmac512::new(std::iter::repeat(0).take(64).collect())],
            id_offset: 1,
            primary: 0,
        }
    }
}

impl CipherProvider for KeySet {
    fn get(&self, context: &[ExtensionField<'_>]) -> Option<CipherHolder<'_>> {
        let mut decoded = None;

        for ef in context {
            if let ExtensionField::NtsCookie(cookie) = ef {
                if decoded.is_some() {
                    // more than one cookie, abort
                    return None;
                }
                decoded = Some(self.decode_cookie(cookie).ok()?);
            }
        }

        decoded.map(CipherHolder::DecodedServerCookie)
    }
}

impl std::fmt::Debug for KeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeySet")
            .field("keys", &self.keys.len())
            .field("id_offset", &self.id_offset)
            .field("primary", &self.primary)
            .finish()
    }
}

#[cfg(any(test, feature = "__internal-fuzz"))]
#[must_use]
pub fn test_cookie() -> DecodedServerCookie {
    DecodedServerCookie {
        algorithm: AeadAlgorithm::AeadAesSivCmac256,
        s2c: Box::new(AesSivCmac256::new((0..32_u8).collect())),
        c2s: Box::new(AesSivCmac256::new((32..64_u8).collect())),
    }
}

#[cfg(test)]
mod tests {

    use std::io::Cursor;

    use super::*;

    #[test]
    fn roundtrip_aes_siv_cmac_256() {
        let decoded = DecodedServerCookie {
            algorithm: AeadAlgorithm::AeadAesSivCmac256,
            s2c: Box::new(AesSivCmac256::new((0..32_u8).collect())),
            c2s: Box::new(AesSivCmac256::new((32..64_u8).collect())),
        };

        let keyset = KeySet {
            keys: vec![AesSivCmac512::new(std::iter::repeat(0).take(64).collect())],
            id_offset: 1,
            primary: 0,
        };

        let encoded = keyset.encode_cookie(&decoded);
        let round = keyset.decode_cookie(&encoded).unwrap();
        assert_eq!(decoded.algorithm, round.algorithm);
        assert_eq!(decoded.s2c.key_bytes(), round.s2c.key_bytes());
        assert_eq!(decoded.c2s.key_bytes(), round.c2s.key_bytes());
    }

    #[test]
    fn test_encode_after_rotate() {
        let decoded = DecodedServerCookie {
            algorithm: AeadAlgorithm::AeadAesSivCmac256,
            s2c: Box::new(AesSivCmac256::new((0..32_u8).collect())),
            c2s: Box::new(AesSivCmac256::new((32..64_u8).collect())),
        };

        let mut provider = KeySetProvider::new(1);
        provider.rotate();
        let keyset = provider.get();

        let encoded = keyset.encode_cookie(&decoded);
        let round = keyset.decode_cookie(&encoded).unwrap();
        assert_eq!(decoded.algorithm, round.algorithm);
        assert_eq!(decoded.s2c.key_bytes(), round.s2c.key_bytes());
        assert_eq!(decoded.c2s.key_bytes(), round.c2s.key_bytes());
    }

    #[test]
    fn can_decode_cookie_with_padding() {
        let decoded = DecodedServerCookie {
            algorithm: AeadAlgorithm::AeadAesSivCmac512,
            s2c: Box::new(AesSivCmac512::new((0..64_u8).collect())),
            c2s: Box::new(AesSivCmac512::new((64..128_u8).collect())),
        };

        let keyset = KeySet {
            keys: vec![AesSivCmac512::new(std::iter::repeat(0).take(64).collect())],
            id_offset: 1,
            primary: 0,
        };

        let mut encoded = keyset.encode_cookie(&decoded);
        encoded.extend([0, 0]);

        let round = keyset.decode_cookie(&encoded).unwrap();
        assert_eq!(decoded.algorithm, round.algorithm);
        assert_eq!(decoded.s2c.key_bytes(), round.s2c.key_bytes());
        assert_eq!(decoded.c2s.key_bytes(), round.c2s.key_bytes());
    }

    #[test]
    fn roundtrip_aes_siv_cmac_512() {
        let decoded = DecodedServerCookie {
            algorithm: AeadAlgorithm::AeadAesSivCmac512,
            s2c: Box::new(AesSivCmac512::new((0..64_u8).collect())),
            c2s: Box::new(AesSivCmac512::new((64..128_u8).collect())),
        };

        let keyset = KeySet {
            keys: vec![AesSivCmac512::new(std::iter::repeat(0).take(64).collect())],
            id_offset: 1,
            primary: 0,
        };

        let encoded = keyset.encode_cookie(&decoded);
        let round = keyset.decode_cookie(&encoded).unwrap();
        assert_eq!(decoded.algorithm, round.algorithm);
        assert_eq!(decoded.s2c.key_bytes(), round.s2c.key_bytes());
        assert_eq!(decoded.c2s.key_bytes(), round.c2s.key_bytes());
    }

    #[test]
    fn test_save_restore() {
        let mut provider = KeySetProvider::new(8);
        provider.rotate();
        provider.rotate();
        let mut output = Cursor::new(vec![]);
        provider.store(&mut output).unwrap();
        let mut input = Cursor::new(output.into_inner());
        let (copy, time) = KeySetProvider::load(&mut input, 8).unwrap();
        assert!(
            std::time::SystemTime::now()
                .duration_since(time)
                .unwrap()
                .as_secs()
                < 2
        );
        assert_eq!(provider.get().primary, copy.get().primary);
        assert_eq!(provider.get().id_offset, copy.get().id_offset);
        for i in 0..provider.get().keys.len() {
            assert_eq!(
                provider.get().keys[i].key_bytes(),
                copy.get().keys[i].key_bytes()
            );
        }
    }

    #[test]
    fn old_cookie_still_valid() {
        let decoded = DecodedServerCookie {
            algorithm: AeadAlgorithm::AeadAesSivCmac256,
            s2c: Box::new(AesSivCmac256::new((0..32_u8).collect())),
            c2s: Box::new(AesSivCmac256::new((32..64_u8).collect())),
        };

        let mut provider = KeySetProvider::new(1);
        let encoded = provider.get().encode_cookie(&decoded);

        let round = provider.get().decode_cookie(&encoded).unwrap();
        assert_eq!(decoded.algorithm, round.algorithm);
        assert_eq!(decoded.s2c.key_bytes(), round.s2c.key_bytes());
        assert_eq!(decoded.c2s.key_bytes(), round.c2s.key_bytes());

        provider.rotate();

        let round = provider.get().decode_cookie(&encoded).unwrap();
        assert_eq!(decoded.algorithm, round.algorithm);
        assert_eq!(decoded.s2c.key_bytes(), round.s2c.key_bytes());
        assert_eq!(decoded.c2s.key_bytes(), round.c2s.key_bytes());

        provider.rotate();

        assert!(provider.get().decode_cookie(&encoded).is_err());
    }

    #[test]
    fn invalid_cookie_length() {
        // this cookie data lies about its length, pretending to be longer than it actually is.
        let input = b"\x23\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x04\x00\x24\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x04\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x04\x00\x28\x00\x10\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

        let provider = KeySetProvider::new(1);

        let output = provider.get().decode_cookie(input);

        assert!(output.is_err());
    }
}
