use aead::generic_array::GenericArray;

use crate::{
    nts_record::AeadAlgorithm,
    packet::{AesSivCmac256, AesSivCmac512, CipherHolder, DecryptError, ExtensionField},
    Cipher, CipherProvider,
};

pub struct DecodedServerCookie {
    pub(crate) algorithm: AeadAlgorithm,
    pub(crate) s2c: Box<dyn Cipher>,
    pub(crate) c2s: Box<dyn Cipher>,
}

impl std::fmt::Debug for DecodedServerCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedServerCookie")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

pub struct KeySet {
    keys: Vec<AesSivCmac512>,
    id_offset: u32,
    primary: u32,
}

impl KeySet {
    #[allow(unused)]
    pub(crate) fn encode_cookie(&self, cookie: &DecodedServerCookie) -> Vec<u8> {
        let mut plaintext =
            Vec::with_capacity(2 + cookie.s2c.key_bytes().len() + cookie.c2s.key_bytes().len());

        plaintext.extend((cookie.algorithm as u16).to_be_bytes());
        plaintext.extend(cookie.s2c.key_bytes());
        plaintext.extend(cookie.c2s.key_bytes());

        let encrypted = self.keys[self.primary as usize]
            .encrypt(&plaintext, &[])
            .expect("Failed to encrypt cookie");

        let mut output = Vec::with_capacity(4 + encrypted.nonce.len() + encrypted.ciphertext.len());
        output.extend((self.primary + self.id_offset).to_be_bytes());
        output.extend(encrypted.nonce);
        output.extend(encrypted.ciphertext);
        output
    }

    #[allow(unused)]
    pub(crate) fn decode_cookie(&self, cookie: &[u8]) -> Result<DecodedServerCookie, DecryptError> {
        if cookie.len() < 20 {
            return Err(DecryptError);
        }

        let id = u32::from_be_bytes(cookie[0..4].try_into().unwrap());

        if id < self.id_offset || (id - self.id_offset) as usize >= self.keys.len() {
            return Err(DecryptError);
        }
        let id = (id - self.id_offset) as usize;

        let plaintext = self.keys[id].decrypt(&cookie[4..20], &cookie[20..], &[])?;

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
}
