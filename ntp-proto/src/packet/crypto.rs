use aes_siv::{siv::Aes128Siv, siv::Aes256Siv, Key, KeyInit};
use rand::Rng;
use tracing::error;

use crate::DecodedServerCookie;

use super::extensionfields::ExtensionField;

#[derive(Debug, thiserror::Error)]
#[error("Could not decrypt ciphertext")]
pub struct DecryptError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionResult {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub trait Cipher: Sync + Send + 'static {
    /// Number of bytes used in the key for this Cipher
    // unlikely to need `self`, but it is required for this trait to be object safe
    fn key_width(&self) -> usize;

    fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> std::io::Result<EncryptionResult>;

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

impl CipherProvider for &dyn Cipher {
    fn get(&self, _context: &[ExtensionField<'_>]) -> Option<CipherHolder<'_>> {
        Some(CipherHolder::Other(*self))
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

impl AesSivCmac256 {
    pub fn new(key: Key<Aes128Siv>) -> Self {
        AesSivCmac256 { key }
    }
}

impl Cipher for AesSivCmac256 {
    fn key_width(&self) -> usize {
        32
    }

    fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> std::io::Result<EncryptionResult> {
        let mut siv = Aes128Siv::new(&self.key);
        let nonce: [u8; 16] = rand::thread_rng().gen();
        let ciphertext = match siv.encrypt([associated_data, &nonce], plaintext) {
            Ok(v) => v,
            Err(e) => {
                // This should probably never happen, so log as an error
                error!(error = ?e, "Encryption failed");
                return Err(std::io::Error::from(std::io::ErrorKind::Other));
            }
        };
        Ok(EncryptionResult {
            nonce: nonce.into(),
            ciphertext,
        })
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

impl Cipher for AesSivCmac512 {
    fn key_width(&self) -> usize {
        32
    }

    fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> std::io::Result<EncryptionResult> {
        let mut siv = Aes256Siv::new(&self.key);
        let nonce: [u8; 16] = rand::thread_rng().gen();
        let ciphertext = match siv.encrypt([associated_data, &nonce], plaintext) {
            Ok(v) => v,
            Err(e) => {
                // This should probably never happen, so log as an error
                error!(error = ?e, "Encryption failed");
                return Err(std::io::Error::from(std::io::ErrorKind::Other));
            }
        };
        Ok(EncryptionResult {
            nonce: nonce.into(),
            ciphertext,
        })
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
