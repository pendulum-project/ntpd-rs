use std::borrow::Borrow;
use std::fmt::Display;

#[cfg(feature = "rustcrypto")]
use aes_siv::{Key, KeyInit, siv::Aes128Siv, siv::Aes256Siv};
use rand::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::keyset::DecodedServerCookie;

use super::extension_fields::ExtensionField;

#[cfg(feature = "openssl")]
mod openssl_defs;
#[cfg(feature = "openssl")]
use openssl_defs::{Aes128Siv, Aes256Siv, Key, SSLName};

#[derive(Debug)]
pub struct DecryptError;

impl Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Could not decrypt ciphertext")
    }
}

impl std::error::Error for DecryptError {}

#[derive(Debug)]
pub struct KeyError;

impl Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid key")
    }
}

impl std::error::Error for KeyError {}

#[cfg(feature = "rustcrypto")]
mod buffer;
#[cfg(feature = "rustcrypto")]
use buffer::Buffer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptResult {
    pub nonce_length: usize,
    pub ciphertext_length: usize,
}

pub trait Cipher: Sync + Send + ZeroizeOnDrop + 'static {
    /// encrypts the plaintext present in the buffer
    ///
    /// - encrypts `plaintext_length` bytes from the buffer
    /// - puts the nonce followed by the ciphertext into the buffer
    /// - returns the size of the nonce and ciphertext
    fn encrypt(
        &self,
        buffer: &mut [u8],
        plaintext_length: usize,
        associated_data: &[u8],
    ) -> std::io::Result<EncryptResult>;

    // MUST support arbitrary length nonces
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

impl AsRef<dyn Cipher> for CipherHolder<'_> {
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

    pub fn key_size() -> usize {
        // prefer trust in compiler optimisation over trust in mental arithmetic
        Self::new(Key::<Aes128Siv>::default()).key.len()
    }

    pub fn try_from(key_bytes: &[u8]) -> Result<Self, KeyError> {
        let bytes = key_bytes.iter();
        (bytes.len() == Self::key_size())
            .then(|| Self {
                key: bytes.copied().collect(),
            })
            .ok_or(KeyError)
    }
}

impl Drop for AesSivCmac256 {
    fn drop(&mut self) {
        // this is necessary so this code doesn't depend on the
        // exact static type -- both a GenericArray as a
        // openssl_defs::Key will implement AsMut.
        AsMut::<[u8]>::as_mut(&mut self.key).zeroize();
    }
}

/// Prepare the buffer for in place encryption by moving the plaintext
/// back, creating space for the nonce.
/// And place the nonce where the caller expects it
fn prepend_nonce<'a>(
    buffer: &'a mut [u8],
    length: usize,
    nonce: &[u8],
) -> std::io::Result<&'a mut [u8]> {
    if buffer.len() < nonce.len() + length {
        return Err(std::io::ErrorKind::WriteZero.into());
    }
    buffer.copy_within(..length, nonce.len());
    buffer[..nonce.len()].copy_from_slice(nonce);

    Ok(&mut buffer[nonce.len()..])
}

impl Cipher for AesSivCmac256 {
    #[cfg(feature = "rustcrypto")]
    fn encrypt(
        &self,
        buffer: &mut [u8],
        plaintext_length: usize,
        associated_data: &[u8],
    ) -> std::io::Result<EncryptResult> {
        let mut siv = Aes128Siv::new(&self.key);
        let nonce: [u8; 16] = rand::thread_rng().r#gen();

        let buffer = prepend_nonce(buffer, plaintext_length, &nonce)?;

        // Create a wrapper around the plaintext portion of the buffer that has
        // the methods aes_siv needs to do encryption in-place.
        let mut buffer_wrap = Buffer::new(buffer, plaintext_length);
        siv.encrypt_in_place([associated_data, &nonce], &mut buffer_wrap)
            .map_err(|_| std::io::ErrorKind::Other)?;

        Ok(EncryptResult {
            nonce_length: nonce.len(),
            ciphertext_length: buffer_wrap.valid(),
        })
    }

    #[cfg(feature = "rustcrypto")]
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

    #[cfg(feature = "openssl")]
    fn encrypt(
        &self,
        buffer: &mut [u8],
        plaintext_length: usize,
        associated_data: &[u8],
    ) -> std::io::Result<EncryptResult> {
        let nonce: [u8; 16] = rand::thread_rng().r#gen();

        let buffer = prepend_nonce(buffer, plaintext_length, &nonce)?;

        let ciphertext_length = openssl_defs::encrypt_in_place(
            &self.key,
            buffer,
            plaintext_length,
            [associated_data, nonce.as_slice()],
        )?;

        Ok(EncryptResult {
            nonce_length: nonce.len(),
            ciphertext_length,
        })
    }

    #[cfg(feature = "openssl")]
    fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        openssl_defs::decrypt_vec(&self.key, ciphertext, [associated_data, nonce])
            .map_err(|_| DecryptError)
    }

    fn key_bytes(&self) -> &[u8] {
        self.key.as_ref()
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
    // this is necessary for call sites where we want to use type-driven inference
    pub fn new(key: Key<Aes256Siv>) -> Self {
        Self { key }
    }

    pub fn key_size() -> usize {
        // prefer trust in compiler optimisation over trust in mental arithmetic
        Self::new(Key::<Aes256Siv>::default()).key.len()
    }

    pub fn try_from(
        key_bytes: impl IntoIterator<Item: Borrow<u8>, IntoIter: ExactSizeIterator>,
    ) -> Result<Self, KeyError> {
        let bytes = key_bytes.into_iter();
        (bytes.len() == Self::key_size())
            .then(|| Self {
                key: bytes.map(|x| *x.borrow()).collect(),
            })
            .ok_or(KeyError)
    }

    pub fn new_random() -> Self {
        #[cfg(feature = "rustcrypto")]
        let key = aes_siv::Aes256SivAead::generate_key(rand::thread_rng());
        #[cfg(feature = "openssl")]
        let key = {
            //NOTE: call sites for this function don't expect failure, maybe that should be adjusted
            let mut key_data = Key::<Aes256Siv>::default();
            let cipher = &openssl::cipher::Cipher::fetch(None, Aes256Siv::name(), None).unwrap();
            let mut ctx = openssl::cipher_ctx::CipherCtx::new().unwrap();
            ctx.encrypt_init(Some(cipher), None, None).unwrap();
            ctx.rand_key(key_data.as_mut()).unwrap();

            key_data
        };

        Self { key }
    }
}

impl ZeroizeOnDrop for AesSivCmac512 {}

impl Drop for AesSivCmac512 {
    fn drop(&mut self) {
        // see above
        AsMut::<[u8]>::as_mut(&mut self.key).zeroize();
    }
}

impl Cipher for AesSivCmac512 {
    #[cfg(feature = "rustcrypto")]
    fn encrypt(
        &self,
        buffer: &mut [u8],
        plaintext_length: usize,
        associated_data: &[u8],
    ) -> std::io::Result<EncryptResult> {
        let mut siv = Aes256Siv::new(&self.key);
        let nonce: [u8; 16] = rand::thread_rng().r#gen();

        let buffer = prepend_nonce(buffer, plaintext_length, &nonce)?;

        // Create a wrapper around the plaintext portion of the buffer that has
        // the methods aes_siv needs to do encryption in-place.
        let mut buffer_wrap = Buffer::new(buffer, plaintext_length);
        siv.encrypt_in_place([associated_data, &nonce], &mut buffer_wrap)
            .map_err(|_| std::io::ErrorKind::Other)?;

        Ok(EncryptResult {
            nonce_length: nonce.len(),
            ciphertext_length: buffer_wrap.valid(),
        })
    }

    #[cfg(feature = "rustcrypto")]
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

    #[cfg(feature = "openssl")]
    fn encrypt(
        &self,
        buffer: &mut [u8],
        plaintext_length: usize,
        associated_data: &[u8],
    ) -> std::io::Result<EncryptResult> {
        let nonce: [u8; 16] = rand::thread_rng().r#gen();

        let buffer = prepend_nonce(buffer, plaintext_length, &nonce)?;

        let ciphertext_length = openssl_defs::encrypt_in_place(
            &self.key,
            buffer,
            plaintext_length,
            [associated_data, nonce.as_slice()],
        )?;

        Ok(EncryptResult {
            nonce_length: nonce.len(),
            ciphertext_length,
        })
    }

    #[cfg(feature = "openssl")]
    fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        openssl_defs::decrypt_vec(&self.key, ciphertext, [associated_data, nonce])
            .map_err(|_| DecryptError)
    }

    fn key_bytes(&self) -> &[u8] {
        self.key.as_ref()
    }
}

// Ensure siv is not shown in debug output
impl std::fmt::Debug for AesSivCmac512 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesSivCmac512").finish()
    }
}

#[cfg(test)]
pub struct IdentityCipher {
    nonce_length: usize,
}

#[cfg(test)]
impl IdentityCipher {
    pub fn new(nonce_length: usize) -> Self {
        Self { nonce_length }
    }
}

#[cfg(test)]
impl ZeroizeOnDrop for IdentityCipher {}

#[cfg(test)]
impl Cipher for IdentityCipher {
    fn encrypt(
        &self,
        buffer: &mut [u8],
        plaintext_length: usize,
        associated_data: &[u8],
    ) -> std::io::Result<EncryptResult> {
        debug_assert!(associated_data.is_empty());

        let nonce: Vec<u8> = (0..self.nonce_length as u8).collect();

        // Prepare the buffer for in place encryption by moving the plaintext
        // back, creating space for the nonce.
        if buffer.len() < nonce.len() + plaintext_length {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        buffer.copy_within(..plaintext_length, nonce.len());
        // And place the nonce where the caller expects it
        buffer[..nonce.len()].copy_from_slice(&nonce);

        Ok(EncryptResult {
            nonce_length: nonce.len(),
            ciphertext_length: plaintext_length,
        })
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        debug_assert!(associated_data.is_empty());

        debug_assert_eq!(nonce.len(), self.nonce_length);

        Ok(ciphertext.to_vec())
    }

    fn key_bytes(&self) -> &[u8] {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_siv_cmac_256() {
        let mut testvec: Vec<u8> = (0..16).collect();
        testvec.resize(testvec.len() + 32, 0);
        let key = AesSivCmac256::new([0u8; 32].into());
        let EncryptResult {
            nonce_length,
            ciphertext_length,
        } = key.encrypt(&mut testvec, 16, &[]).unwrap();
        let result = key
            .decrypt(
                &testvec[..nonce_length],
                &testvec[nonce_length..(nonce_length + ciphertext_length)],
                &[],
            )
            .unwrap();
        assert_eq!(result, (0..16).collect::<Vec<u8>>());
    }

    #[test]
    fn test_aes_siv_cmac_256_with_assoc_data() {
        let mut testvec: Vec<u8> = (0..16).collect();
        testvec.resize(testvec.len() + 32, 0);
        let key = AesSivCmac256::new([0u8; 32].into());
        let EncryptResult {
            nonce_length,
            ciphertext_length,
        } = key.encrypt(&mut testvec, 16, &[1]).unwrap();
        assert!(
            key.decrypt(
                &testvec[..nonce_length],
                &testvec[nonce_length..(nonce_length + ciphertext_length)],
                &[2]
            )
            .is_err()
        );
        let result = key
            .decrypt(
                &testvec[..nonce_length],
                &testvec[nonce_length..(nonce_length + ciphertext_length)],
                &[1],
            )
            .unwrap();
        assert_eq!(result, (0..16).collect::<Vec<u8>>());
    }

    #[test]
    fn test_aes_siv_cmac_512() {
        let mut testvec: Vec<u8> = (0..16).collect();
        testvec.resize(testvec.len() + 32, 0);
        let key = AesSivCmac512::new([0u8; 64].into());
        let EncryptResult {
            nonce_length,
            ciphertext_length,
        } = key.encrypt(&mut testvec, 16, &[]).unwrap();
        let result = key
            .decrypt(
                &testvec[..nonce_length],
                &testvec[nonce_length..(nonce_length + ciphertext_length)],
                &[],
            )
            .unwrap();
        assert_eq!(result, (0..16).collect::<Vec<u8>>());
    }

    #[test]
    fn test_aes_siv_cmac_512_with_assoc_data() {
        let mut testvec: Vec<u8> = (0..16).collect();
        testvec.resize(testvec.len() + 32, 0);
        let key = AesSivCmac512::new([0u8; 64].into());
        let EncryptResult {
            nonce_length,
            ciphertext_length,
        } = key.encrypt(&mut testvec, 16, &[1]).unwrap();
        assert!(
            key.decrypt(
                &testvec[..nonce_length],
                &testvec[nonce_length..(nonce_length + ciphertext_length)],
                &[2]
            )
            .is_err()
        );
        let result = key
            .decrypt(
                &testvec[..nonce_length],
                &testvec[nonce_length..(nonce_length + ciphertext_length)],
                &[1],
            )
            .unwrap();
        assert_eq!(result, (0..16).collect::<Vec<u8>>());
    }

    #[test]
    fn key_functions_correctness() {
        assert_eq!(
            std::mem::size_of::<Key<Aes128Siv>>(),
            AesSivCmac256::key_size()
        );
        assert_eq!(
            std::mem::size_of::<Key<Aes256Siv>>(),
            AesSivCmac512::key_size()
        );

        let key_bytes = (1..=64).collect::<Vec<u8>>();
        assert!(AesSivCmac256::try_from(&key_bytes).is_err());

        let slice = &key_bytes[..AesSivCmac256::key_size()];
        assert_eq!(AesSivCmac256::try_from(slice).unwrap().key_bytes(), slice);

        let slice = &key_bytes[..AesSivCmac512::key_size()];
        assert_eq!(AesSivCmac512::try_from(slice).unwrap().key_bytes(), slice);
    }
}
