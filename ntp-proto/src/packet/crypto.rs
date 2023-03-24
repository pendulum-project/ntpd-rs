use aead::Buffer;
use aes_siv::{siv::Aes128Siv, siv::Aes256Siv, Key, KeyInit};
use rand::Rng;
use tracing::error;

use crate::DecodedServerCookie;

use super::extensionfields::ExtensionField;

#[derive(Debug, thiserror::Error)]
#[error("Could not decrypt ciphertext")]
pub struct DecryptError;

struct SliceBuffer<'a> {
    buffer: &'a mut [u8],
    valid: usize,
}

impl<'a> AsMut<[u8]> for SliceBuffer<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[..self.valid]
    }
}

impl<'a> AsRef<[u8]> for SliceBuffer<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.valid]
    }
}

impl<'a> Buffer for SliceBuffer<'a> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aead::Result<()> {
        if self.valid + other.len() < self.buffer.len() {
            self.buffer[self.valid..][..other.len()].copy_from_slice(other);
            self.valid += other.len();
            Ok(())
        } else {
            Err(aead::Error)
        }
    }

    fn truncate(&mut self, len: usize) {
        self.valid = self.valid.min(len);
    }
}

pub trait Cipher: Sync + Send + 'static {
    fn encrypt_in_place_detached(
        &self,
        plaintext: &mut [u8],
        associated_data: &[u8],
    ) -> std::io::Result<(aes_siv::Tag, aes_siv::Nonce)>;

    fn encrypt_in_buffer(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
        output_buffer: &mut [u8],
    ) -> std::io::Result<(usize, usize)>;

    fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DecryptError>;

    fn decrypt_in_place(
        &self,
        nonce: &[u8],
        ciphertext: &mut [u8],
        associated_data: &[u8],
    ) -> Result<usize, DecryptError>;

    fn key_bytes(&self) -> &[u8];
}

pub enum CipherHolder<'a> {
    DecodedServerCookie(DecodedServerCookie),
    Other(&'a dyn Cipher),
}

impl<'a> AsRef<dyn Cipher> for CipherHolder<'a> {
    fn as_ref(&self) -> &dyn Cipher {
        match self {
            CipherHolder::DecodedServerCookie(cookie) => cookie.c2s.as_ref(),
            CipherHolder::Other(cipher) => *cipher,
        }
    }
}

pub trait CipherProvider {
    fn get<'a>(
        &'a self,
        context: impl Iterator<Item = ExtensionField<'a>> + 'a,
    ) -> Option<CipherHolder<'a>>;
}

pub struct NoCipher;

impl CipherProvider for NoCipher {
    fn get<'a>(
        &'a self,
        _context: impl Iterator<Item = ExtensionField<'a>> + 'a,
    ) -> Option<CipherHolder<'a>> {
        None
    }
}

impl CipherProvider for dyn Cipher {
    fn get<'a>(
        &'a self,
        _context: impl Iterator<Item = ExtensionField<'a>> + 'a,
    ) -> Option<CipherHolder<'a>> {
        Some(CipherHolder::Other(self))
    }
}

impl CipherProvider for Option<&dyn Cipher> {
    fn get<'a>(
        &'a self,
        _context: impl Iterator<Item = ExtensionField<'a>> + 'a,
    ) -> Option<CipherHolder<'a>> {
        self.map(CipherHolder::Other)
    }
}

impl<C: Cipher> CipherProvider for C {
    fn get<'a>(
        &'a self,
        _context: impl Iterator<Item = ExtensionField<'a>> + 'a,
    ) -> Option<CipherHolder<'a>> {
        Some(CipherHolder::Other(self))
    }
}

impl<C: Cipher> CipherProvider for Option<C> {
    fn get<'a>(
        &'a self,
        _context: impl Iterator<Item = ExtensionField<'a>> + 'a,
    ) -> Option<CipherHolder<'a>> {
        self.as_ref().map(|v| CipherHolder::Other(v))
    }
}

pub struct AesSivCmac256 {
    // 128 vs 256 difference is due to using the official name (us) vs
    // the number of bits of security (aes_siv crate)
    key: Key<Aes128Siv>,
}

impl AesSivCmac256 {
    pub fn new(key: Key<Aes128Siv>) -> Self {
        AesSivCmac256 { key }
    }
}

impl Cipher for AesSivCmac256 {
    fn encrypt_in_place_detached(
        &self,
        plaintext: &mut [u8],
        associated_data: &[u8],
    ) -> std::io::Result<(aes_siv::Tag, aes_siv::Nonce)> {
        let mut siv = Aes128Siv::new(&self.key);
        let nonce: [u8; 16] = rand::thread_rng().gen();

        let siv_tag = match siv.encrypt_in_place_detached([associated_data, &nonce], plaintext) {
            Ok(tag) => tag,
            Err(e) => {
                // This should probably never happen, so log as an error
                error!(error = ?e, "Encryption failed");
                return Err(std::io::Error::from(std::io::ErrorKind::Other));
            }
        };

        Ok((siv_tag, nonce.into()))
    }

    fn encrypt_in_buffer(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
        output_buffer: &mut [u8],
    ) -> std::io::Result<(usize, usize)> {
        if output_buffer.len() < 16 + plaintext.len() {
            error!("Output buffer for encryption undersized");
            return Err(std::io::Error::from(std::io::ErrorKind::Other));
        }

        let mut siv = Aes128Siv::new(&self.key);
        let nonce: [u8; 16] = rand::thread_rng().gen();

        output_buffer[..16].copy_from_slice(&nonce);
        output_buffer[16..][..plaintext.len()].copy_from_slice(plaintext);
        let mut buffer = SliceBuffer{ buffer: &mut output_buffer[16..], valid: plaintext.len() };
        siv.encrypt_in_place([associated_data, &nonce], &mut buffer).map_err(|e| {
            error!(error = ?e, "Encryption failed");
            std::io::Error::from(std::io::ErrorKind::Other)
        })?;

        Ok((nonce.len(), buffer.valid))
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        let mut siv = Aes128Siv::new(&self.key);
        siv.decrypt([associated_data, nonce], ciphertext)
            .map_err(|_| DecryptError)
    }

    fn decrypt_in_place(
        &self,
        nonce: &[u8],
        ciphertext: &mut [u8],
        associated_data: &[u8],
    ) -> Result<usize, DecryptError> {
        let mut siv = Aes128Siv::new(&self.key);
        let mut buffer = SliceBuffer {
            valid: ciphertext.len(),
            buffer: ciphertext,
        };
        siv.decrypt_in_place([associated_data, nonce], &mut buffer)
            .map_err(|_| DecryptError)?;
        Ok(buffer.valid)
    }

    fn key_bytes(&self) -> &[u8] {
        &self.key
    }
}

// Ensure siv is not shown in debug output
impl std::fmt::Debug for AesSivCmac256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesSivCmac256").finish()
    }
}

pub struct AesSivCmac512 {
    // 256 vs 512 difference is due to using the official name (us) vs
    // the number of bits of security (aes_siv crate)
    key: Key<Aes256Siv>,
}

impl AesSivCmac512 {
    pub fn new(key: Key<Aes256Siv>) -> Self {
        AesSivCmac512 { key }
    }
}

impl Cipher for AesSivCmac512 {
    fn encrypt_in_place_detached(
        &self,
        plaintext: &mut [u8],
        associated_data: &[u8],
    ) -> std::io::Result<(aes_siv::Tag, aes_siv::Nonce)> {
        let mut siv = Aes256Siv::new(&self.key);
        let nonce: [u8; 16] = rand::thread_rng().gen();

        let siv_tag = match siv.encrypt_in_place_detached([associated_data, &nonce], plaintext) {
            Ok(tag) => tag,
            Err(e) => {
                // This should probably never happen, so log as an error
                error!(error = ?e, "Encryption failed");
                return Err(std::io::Error::from(std::io::ErrorKind::Other));
            }
        };

        Ok((siv_tag, nonce.into()))
    }

    fn encrypt_in_buffer(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
        output_buffer: &mut [u8],
    ) -> std::io::Result<(usize, usize)> {
        if output_buffer.len() < 16 + plaintext.len() {
            error!("Output buffer for encryption undersized");
            return Err(std::io::Error::from(std::io::ErrorKind::Other));
        }

        let mut siv = Aes256Siv::new(&self.key);
        let nonce: [u8; 16] = rand::thread_rng().gen();

        output_buffer[..16].copy_from_slice(&nonce);
        output_buffer[16..][..plaintext.len()].copy_from_slice(plaintext);
        let mut buffer = SliceBuffer{ buffer: &mut output_buffer[16..], valid: plaintext.len() };
        siv.encrypt_in_place([associated_data, &nonce], &mut buffer).map_err(|e| {
            error!(error = ?e, "Encryption failed");
            std::io::Error::from(std::io::ErrorKind::Other)
        })?;

        Ok((nonce.len(), buffer.valid))
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        let mut siv = Aes256Siv::new(&self.key);
        siv.decrypt([associated_data, nonce], ciphertext)
            .map_err(|_| DecryptError)
    }

    fn decrypt_in_place(
        &self,
        nonce: &[u8],
        ciphertext: &mut [u8],
        associated_data: &[u8],
    ) -> Result<usize, DecryptError> {
        let mut siv = Aes256Siv::new(&self.key);
        let mut buffer = SliceBuffer {
            valid: ciphertext.len(),
            buffer: ciphertext,
        };
        siv.decrypt_in_place([associated_data, nonce], &mut buffer)
            .map_err(|_| DecryptError)?;
        Ok(buffer.valid)
    }

    fn key_bytes(&self) -> &[u8] {
        &self.key
    }
}

// Ensure siv is not shown in debug output
impl std::fmt::Debug for AesSivCmac512 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesSivCmac512").finish()
    }
}
