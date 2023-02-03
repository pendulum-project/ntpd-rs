use aes_siv::{siv::Aes128Siv, Key, KeyInit};
use rand::Rng;
use tracing::error;

use super::{extensionfields::ExtensionField, PacketParsingError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionResult {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub trait Cipher: Sync + Send {
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
    ) -> Result<Vec<u8>, PacketParsingError>;
}

pub trait CipherProvider {
    fn get(&self, context: &[ExtensionField<'_>]) -> Option<&dyn Cipher>;
}

impl CipherProvider for () {
    fn get<'a>(&self, _context: &[ExtensionField<'_>]) -> Option<&dyn Cipher> {
        None
    }
}

impl CipherProvider for &dyn Cipher {
    fn get(&self, _context: &[ExtensionField<'_>]) -> Option<&dyn Cipher> {
        Some(*self)
    }
}

impl CipherProvider for Option<&dyn Cipher> {
    fn get(&self, _context: &[ExtensionField<'_>]) -> Option<&dyn Cipher> {
        *self
    }
}

impl<C: Cipher> CipherProvider for C {
    fn get(&self, _context: &[ExtensionField<'_>]) -> Option<&dyn Cipher> {
        Some(self)
    }
}

impl<C: Cipher> CipherProvider for Option<C> {
    fn get(&self, _context: &[ExtensionField<'_>]) -> Option<&dyn Cipher> {
        self.as_ref().map(|v| v as &dyn Cipher)
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
    ) -> Result<Vec<u8>, PacketParsingError> {
        let mut siv = Aes128Siv::new(&self.key);
        siv.decrypt([associated_data, nonce], ciphertext)
            .map_err(|_| PacketParsingError::DecryptError)
    }
}

// Ensure siv is not shown in debug output
impl std::fmt::Debug for AesSivCmac256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesSivCmac256").finish()
    }
}
