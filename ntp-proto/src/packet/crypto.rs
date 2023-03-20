use aes_siv::{siv::Aes128Siv, siv::Aes256Siv, Key, KeyInit};
use rand::Rng;
use tracing::error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::DecodedServerCookie;

use super::extensionfields::ExtensionField;

#[derive(Debug, thiserror::Error)]
#[error("Could not decrypt ciphertext")]
pub struct DecryptError;

pub trait Cipher: Sync + Send + ZeroizeOnDrop + 'static {
    fn encrypt_in_place_detached(
        &self,
        plaintext: &mut [u8],
        associated_data: &[u8],
    ) -> std::io::Result<(aes_siv::Tag, aes_siv::Nonce)>;

    fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DecryptError>;

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
    fn get(&self, context: &[ExtensionField<'_>]) -> Option<CipherHolder<'_>>;
}

pub struct NoCipher;

impl CipherProvider for NoCipher {
    fn get<'a>(&self, _context: &[ExtensionField<'_>]) -> Option<CipherHolder<'_>> {
        None
    }
}

impl CipherProvider for dyn Cipher {
    fn get(&self, _context: &[ExtensionField<'_>]) -> Option<CipherHolder<'_>> {
        Some(CipherHolder::Other(self))
    }
}

impl CipherProvider for Option<&dyn Cipher> {
    fn get(&self, _context: &[ExtensionField<'_>]) -> Option<CipherHolder<'_>> {
        self.map(CipherHolder::Other)
    }
}

impl<C: Cipher> CipherProvider for C {
    fn get(&self, _context: &[ExtensionField<'_>]) -> Option<CipherHolder<'_>> {
        Some(CipherHolder::Other(self))
    }
}

impl<C: Cipher> CipherProvider for Option<C> {
    fn get(&self, _context: &[ExtensionField<'_>]) -> Option<CipherHolder<'_>> {
        self.as_ref().map(|v| CipherHolder::Other(v))
    }
}

pub struct AesSivCmac256 {
    // 128 vs 256 difference is due to using the official name (us) vs
    // the number of bits of security (aes_siv crate)
    key: Key<Aes128Siv>,
}

impl ZeroizeOnDrop for AesSivCmac256 {}

impl AesSivCmac256 {
    pub fn new(key: Key<Aes128Siv>) -> Self {
        AesSivCmac256 { key }
    }
}

impl Drop for AesSivCmac256 {
    fn drop(&mut self) {
        self.key.zeroize()
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

impl ZeroizeOnDrop for AesSivCmac512 {}

impl Drop for AesSivCmac512 {
    fn drop(&mut self) {
        self.key.zeroize()
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
