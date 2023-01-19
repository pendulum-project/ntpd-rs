use aead::{Aead, AeadCore};
use aes_siv::{Aes128SivAead, Nonce, SivAead};
use rand::{CryptoRng, RngCore};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
enum AeadAlgorithm {
    AEAD_AES_SIV_CMAC_256 = 15,
}

impl AeadAlgorithm {
    fn serialize(self) -> u8 {
        self as u8
    }

    fn deserialize(algorithm: u8) -> Option<Self> {
        match algorithm {
            15 => Some(Self::AEAD_AES_SIV_CMAC_256),
            _ => None,
        }
    }

    const fn key_size(&self) -> usize {
        match self {
            AeadAlgorithm::AEAD_AES_SIV_CMAC_256 => 32,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct NtsCookie {
    algorithm: AeadAlgorithm,
    s2c: Vec<u8>,
    c2s: Vec<u8>,
}

impl NtsCookie {
    fn serialize(&self, server_key: &MasterKey, identifier: u32) -> Result<Vec<u8>, aead::Error> {
        let mut plaintext = Vec::with_capacity(1 + self.s2c.len() + self.c2s.len());

        plaintext.push(self.algorithm.serialize());
        plaintext.extend(self.s2c.iter());
        plaintext.extend(self.c2s.iter());

        let nonce = Aes128SivAead::generate_nonce(rand::thread_rng());
        let ciphertext = server_key.key.encrypt(&nonce, plaintext.as_slice())?;

        plaintext.clear();

        let mut output = plaintext;

        output.extend(identifier.to_le_bytes());
        output.extend(&nonce);
        output.extend(ciphertext);

        Ok(output)
    }

    fn deserialize<'k, F>(identifier_to_key: F, bytes: &[u8]) -> Option<Self>
    where
        F: FnOnce(u32) -> (&'k MasterKey, AeadAlgorithm),
    {
        if bytes.len() < 4 + 16 + 16 {
            tracing::error!("cookie bytes are too short");
            return None;
        }

        let identifier = u32::from_le_bytes(bytes[0..][..4].try_into().unwrap());
        let nonce = &bytes[4..][..16];
        let ciphertext = &bytes[4 + 16..];

        let (master_key, expected_algorithm) = identifier_to_key(identifier);

        let plaintext = master_key.key.decrypt(nonce.into(), ciphertext).unwrap();

        if plaintext.len() != 1 + 2 * expected_algorithm.key_size() {
            tracing::error!("plaintext has incorect size");
            return None;
        }

        let algorithm = AeadAlgorithm::deserialize(plaintext[0])?;
        if expected_algorithm != algorithm {
            tracing::error!("cookie algorithm mismatch");
            return None;
        }

        let key_size = algorithm.key_size();

        match algorithm {
            AeadAlgorithm::AEAD_AES_SIV_CMAC_256 => {
                let (s2c, c2s) = plaintext[1..].split_at(key_size);

                debug_assert_eq!(s2c.len(), key_size);
                debug_assert_eq!(c2s.len(), key_size);

                Some(Self {
                    algorithm,
                    s2c: s2c.to_vec(),
                    c2s: c2s.to_vec(),
                })
            }
        }
    }
}

struct MasterKey {
    key: Aes128SivAead,
}

impl MasterKey {
    const KEY_SIZE: usize = 32;
}

impl Default for MasterKey {
    fn default() -> Self {
        use aes_siv::KeyInit;

        let key: aead::Key<Aes128SivAead> = Default::default();
        Self {
            key: Aes128SivAead::new(&key),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn roundtrip() {
        let algorithm = AeadAlgorithm::AEAD_AES_SIV_CMAC_256;

        let numbers: Vec<u8> = (0..2 * algorithm.key_size() as u8).collect();
        let s2c = numbers[..algorithm.key_size()].to_vec();
        let c2s = numbers[algorithm.key_size()..].to_vec();

        let cookie = NtsCookie {
            algorithm,
            s2c,
            c2s,
        };

        let master_key = MasterKey::default();

        let identifier = 0;
        let encrypted = cookie.serialize(&master_key, identifier).unwrap();

        let identifier_to_key = |id| {
            assert_eq!(id, identifier);

            (&master_key, algorithm)
        };

        let decrypted = NtsCookie::deserialize(identifier_to_key, &encrypted).unwrap();

        assert_eq!(cookie, decrypted)
    }
}
