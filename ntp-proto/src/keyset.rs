use std::{
    io::{Read, Write},
    sync::Arc,
};

use aead::{generic_array::GenericArray, KeyInit};

use crate::{
    arrayvec::ArrayVec,
    nts_record::AeadAlgorithm,
    packet::{AesSivCmac256, AesSivCmac512, CipherHolder, DecryptError, ExtensionField},
    Cipher, CipherProvider,
};

pub struct DecodedServerCookie {
    pub(crate) algorithm: AeadAlgorithm,
    pub s2c: Box<dyn Cipher>,
    pub c2s: Box<dyn Cipher>,
}

impl std::fmt::Debug for DecodedServerCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedServerCookie")
            .field("algorithm", &self.algorithm)
            .finish()
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

    /// Rotate a new key in as primary, forgetting an old one if needed
    pub fn rotate(&mut self) {
        let next_key = AesSivCmac512::new(aes_siv::Aes256SivAead::generate_key(rand::thread_rng()));
        let mut keys = Vec::with_capacity((self.history + 1).min(self.current.keys.len() + 1));
        for key in self.current.keys
            [self.current.keys.len().saturating_sub(self.history)..self.current.keys.len()]
            .iter()
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
            primary: keys.len() as u32,
            keys,
        })
    }

    pub fn load(
        reader: &mut impl Read,
        history: usize,
    ) -> std::io::Result<(Self, std::time::SystemTime)> {
        let mut buf = [0; 64];
        reader.read_exact(&mut buf[0..20])?;
        let time = std::time::SystemTime::UNIX_EPOCH
            + std::time::Duration::from_secs(u64::from_be_bytes(buf[0..8].try_into().unwrap()));
        let id_offset = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        let primary = u32::from_be_bytes(buf[12..16].try_into().unwrap());
        let len = u32::from_be_bytes(buf[16..20].try_into().unwrap());
        if primary > len {
            return Err(std::io::ErrorKind::Other.into());
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

    pub fn store(&self, writer: &mut impl Write) -> std::io::Result<()> {
        let time = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("Could not get current time");
        writer.write_all(&time.as_secs().to_be_bytes())?;
        writer.write_all(&self.current.id_offset.to_be_bytes())?;
        writer.write_all(&self.current.primary.to_be_bytes())?;
        writer.write_all(&(self.current.keys.len() as u32).to_be_bytes())?;
        for key in self.current.keys.iter() {
            writer.write_all(key.key_bytes())?;
        }
        Ok(())
    }

    /// Get the current KeySet
    pub fn get(&self) -> Arc<KeySet> {
        self.current.clone()
    }
}

pub struct KeySet {
    keys: Vec<AesSivCmac512>,
    id_offset: u32,
    primary: u32,
}

impl KeySet {
    const MAX_PLAINTEXT_BYTES: usize = 2 + 64 + 64;

    fn plaintext(cookie: &DecodedServerCookie) -> ArrayVec<{ Self::MAX_PLAINTEXT_BYTES }> {
        let mut plaintext = ArrayVec::default();

        let actual_length = 2 + cookie.s2c.key_bytes().len() + cookie.c2s.key_bytes().len();
        debug_assert!(actual_length <= plaintext.capacity());

        // we have just asserted that these will fit, so can ignore errors
        let algorithm_bytes = (cookie.algorithm as u16).to_be_bytes();
        plaintext.write_all(&algorithm_bytes).unwrap();
        plaintext.write_all(cookie.s2c.key_bytes()).unwrap();
        plaintext.write_all(cookie.c2s.key_bytes()).unwrap();

        plaintext
    }

    #[cfg(feature = "fuzz")]
    pub fn encode_cookie_pub(&self, cookie: &DecodedServerCookie) -> Vec<u8> {
        self.encode_cookie(cookie)
    }

    pub(crate) fn encode_cookie(&self, cookie: &DecodedServerCookie) -> Vec<u8> {
        let mut plaintext = Self::plaintext(cookie);
        let plaintext_len = plaintext.as_slice().len();

        let (siv_tag, nonce) = self.keys[self.primary as usize]
            .encrypt_in_place_detached(plaintext.as_mut(), &[])
            .expect("Failed to encrypt cookie");

        let ciphertext = plaintext.as_slice();
        let ciphertext_len = siv_tag.len() + ciphertext.len();

        debug_assert_eq!(plaintext_len + 16, ciphertext_len);

        let mut output = Vec::with_capacity(4 + nonce.len() + ciphertext_len);
        output.extend((self.primary.wrapping_add(self.id_offset)).to_be_bytes());
        output.extend((ciphertext_len as u16).to_be_bytes());
        output.extend(nonce);
        output.extend(siv_tag);
        output.extend(ciphertext);
        output
    }

    #[cfg(feature = "fuzz")]
    pub fn decode_cookie_pub(&self, cookie: &[u8]) -> Result<DecodedServerCookie, DecryptError> {
        self.decode_cookie(cookie)
    }

    pub(crate) fn decode_cookie(&self, cookie: &[u8]) -> Result<DecodedServerCookie, DecryptError> {
        if cookie.len() < 22 {
            return Err(DecryptError);
        }

        let id = u32::from_be_bytes(cookie[0..4].try_into().unwrap());
        let id = id.wrapping_sub(self.id_offset) as usize;
        if id >= self.keys.len() {
            return Err(DecryptError);
        }

        let cipher_text_length = u16::from_be_bytes([cookie[4], cookie[5]]) as usize;

        let nonce = &cookie[6..22];
        let ciphertext = cookie[22..].get(..cipher_text_length).ok_or(DecryptError)?;
        let plaintext = self.keys[id].decrypt(nonce, ciphertext, &[])?;

        let algorithm =
            AeadAlgorithm::try_deserialize(u16::from_be_bytes(plaintext[0..2].try_into().unwrap()))
                .ok_or(DecryptError)?;

        Ok(match algorithm {
            AeadAlgorithm::AeadAesSivCmac256 => {
                if plaintext.len() != 2 + 32 + 32 {
                    return Err(DecryptError);
                }
                DecodedServerCookie {
                    algorithm,
                    s2c: Box::new(AesSivCmac256::new(GenericArray::clone_from_slice(
                        &plaintext[2..34],
                    ))),
                    c2s: Box::new(AesSivCmac256::new(GenericArray::clone_from_slice(
                        &plaintext[34..66],
                    ))),
                }
            }
            AeadAlgorithm::AeadAesSivCmac512 => {
                if plaintext.len() != 2 + 64 + 64 {
                    return Err(DecryptError);
                }
                DecodedServerCookie {
                    algorithm,
                    s2c: Box::new(AesSivCmac512::new(GenericArray::clone_from_slice(
                        &plaintext[2..66],
                    ))),
                    c2s: Box::new(AesSivCmac512::new(GenericArray::clone_from_slice(
                        &plaintext[66..130],
                    ))),
                }
            }
        })
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
                decoded = Some(self.decode_cookie(cookie).ok()?)
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
