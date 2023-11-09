use std::io::Write;

use aes_siv::{siv::Aes128Siv, siv::Aes256Siv, Key, KeyInit};
use ed25519_dalek::{Signer, Verifier};
use rand::Rng;
use tracing::error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{keyset::DecodedServerCookie, NtpTimestamp};

use super::extension_fields::ExtensionField;

#[derive(Debug, thiserror::Error)]
#[error("Could not decrypt ciphertext")]
pub struct DecryptError;

struct Buffer<'a> {
    buffer: &'a mut [u8],
    valid: usize,
}

impl<'a> Buffer<'a> {
    fn new(buffer: &'a mut [u8], valid: usize) -> Self {
        Self { buffer, valid }
    }

    fn valid(&self) -> usize {
        self.valid
    }
}

impl<'a> AsMut<[u8]> for Buffer<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[..self.valid]
    }
}

impl<'a> AsRef<[u8]> for Buffer<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.valid]
    }
}

impl<'a> aead::Buffer for Buffer<'a> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aead::Result<()> {
        self.buffer
            .get_mut(self.valid..(self.valid + other.len()))
            .ok_or(aead::Error)?
            .copy_from_slice(other);
        self.valid += other.len();
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.valid = std::cmp::min(self.valid, len);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptResult {
    pub nonce_length: usize,
    pub ciphertext_length: usize,
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherType {
    #[default]
    None,
    Nts,
    Ed25519,
}

pub trait Cipher: Sync + Send + ZeroizeOnDrop + 'static {
    /// Type of encryption for which the cipher provides
    /// services.
    fn etype(&self) -> CipherType;

    /// encrypts the plaintext present in the buffer
    ///
    /// For NTS type ciphers it should:
    /// - encrypts `plaintext_length` bytes from the buffer
    /// - puts the nonce followed by the ciphertext into the buffer
    /// - returns the size of the nonce and ciphertext
    ///
    /// For Ed25519 type ciphers it should
    /// - Write a certificate of the short-term key signed with the long term key
    /// - Put a signature of the asociated data into the buffer as ciphertext
    /// - return the size of the ciphertext and that of the certificate as nonce_length
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
        transmit_timestamp: NtpTimestamp,
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
    fn get(&self, etype: CipherType, context: &[ExtensionField<'_>]) -> Option<CipherHolder<'_>>;
}

pub struct NoCipher;

impl ZeroizeOnDrop for NoCipher {}

impl Cipher for NoCipher {
    fn etype(&self) -> CipherType {
        CipherType::None
    }

    fn encrypt(
        &self,
        _buffer: &mut [u8],
        _plaintext_length: usize,
        _associated_data: &[u8],
    ) -> std::io::Result<EncryptResult> {
        Err(std::io::ErrorKind::Other.into())
    }

    fn decrypt(
        &self,
        _nonce: &[u8],
        _ciphertext: &[u8],
        _associated_data: &[u8],
        _transmit_timestamp: NtpTimestamp,
    ) -> Result<Vec<u8>, DecryptError> {
        Err(DecryptError)
    }

    fn key_bytes(&self) -> &[u8] {
        &[]
    }
}

impl CipherProvider for dyn Cipher {
    fn get(&self, etype: CipherType, _context: &[ExtensionField<'_>]) -> Option<CipherHolder<'_>> {
        if self.etype() == etype {
            Some(CipherHolder::Other(self))
        } else {
            None
        }
    }
}

impl CipherProvider for Option<&dyn Cipher> {
    fn get(&self, etype: CipherType, _context: &[ExtensionField<'_>]) -> Option<CipherHolder<'_>> {
        self.filter(|c| c.etype() == etype).map(CipherHolder::Other)
    }
}

impl<C: Cipher> CipherProvider for C {
    fn get(&self, etype: CipherType, _context: &[ExtensionField<'_>]) -> Option<CipherHolder<'_>> {
        if self.etype() == etype {
            Some(CipherHolder::Other(self))
        } else {
            None
        }
    }
}

impl<C: Cipher> CipherProvider for Option<C> {
    fn get(&self, etype: CipherType, _context: &[ExtensionField<'_>]) -> Option<CipherHolder<'_>> {
        self.as_ref()
            .filter(|c| c.etype() == etype)
            .map(|v| CipherHolder::Other(v))
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
        self.key.zeroize();
    }
}

impl Cipher for AesSivCmac256 {
    fn etype(&self) -> CipherType {
        CipherType::Nts
    }

    fn encrypt(
        &self,
        buffer: &mut [u8],
        plaintext_length: usize,
        associated_data: &[u8],
    ) -> std::io::Result<EncryptResult> {
        let mut siv = Aes128Siv::new(&self.key);
        let nonce: [u8; 16] = rand::thread_rng().gen();

        // Prepare the buffer for in place encryption by moving the plaintext
        // back, creating space for the nonce.
        if buffer.len() < nonce.len() + plaintext_length {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        buffer.copy_within(..plaintext_length, nonce.len());
        // And place the nonce where the caller expects it
        buffer[..nonce.len()].copy_from_slice(&nonce);

        // Create a wrapper around the plaintext portion of the buffer that has
        // the methods aes_siv needs to do encryption in-place.
        let mut buffer_wrap = Buffer::new(&mut buffer[nonce.len()..], plaintext_length);
        siv.encrypt_in_place([associated_data, &nonce], &mut buffer_wrap)
            .map_err(|_| std::io::ErrorKind::Other)?;

        Ok(EncryptResult {
            nonce_length: nonce.len(),
            ciphertext_length: buffer_wrap.valid(),
        })
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
        _transmit_timestamp: NtpTimestamp,
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
        self.key.zeroize();
    }
}

impl Cipher for AesSivCmac512 {
    fn etype(&self) -> CipherType {
        CipherType::Nts
    }

    fn encrypt(
        &self,
        buffer: &mut [u8],
        plaintext_length: usize,
        associated_data: &[u8],
    ) -> std::io::Result<EncryptResult> {
        let mut siv = Aes256Siv::new(&self.key);
        let nonce: [u8; 16] = rand::thread_rng().gen();

        // Prepare the buffer for in place encryption by moving the plaintext
        // back, creating space for the nonce.
        if buffer.len() < nonce.len() + plaintext_length {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        buffer.copy_within(..plaintext_length, nonce.len());
        // And place the nonce where the caller expects it
        buffer[..nonce.len()].copy_from_slice(&nonce);

        // Create a wrapper around the plaintext portion of the buffer that has
        // the methods aes_siv needs to do encryption in-place.
        let mut buffer_wrap = Buffer::new(&mut buffer[nonce.len()..], plaintext_length);
        siv.encrypt_in_place([associated_data, &nonce], &mut buffer_wrap)
            .map_err(|_| std::io::ErrorKind::Other)?;

        Ok(EncryptResult {
            nonce_length: nonce.len(),
            ciphertext_length: buffer_wrap.valid(),
        })
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
        _transmit_timestamp: NtpTimestamp,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519Public {
    public_key: ed25519_dalek::VerifyingKey,
}

impl Ed25519Public {
    pub fn new(key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH]) -> Option<Self> {
        Some(Ed25519Public {
            public_key: ed25519_dalek::VerifyingKey::from_bytes(&key).ok()?,
        })
    }
}

// This is a white lie, we don't leak anything problematic on drop
impl ZeroizeOnDrop for Ed25519Public {}

impl Cipher for Ed25519Public {
    fn etype(&self) -> CipherType {
        CipherType::Ed25519
    }

    fn encrypt(
        &self,
        _buffer: &mut [u8],
        _plaintext_length: usize,
        _associated_data: &[u8],
    ) -> std::io::Result<EncryptResult> {
        // Can't encrypt with a public key
        Err(std::io::ErrorKind::Other.into())
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
        transmit_timestamp: NtpTimestamp,
    ) -> Result<Vec<u8>, DecryptError> {
        if nonce.len() != 104 {
            return Err(DecryptError);
        }
        if ciphertext.len() != 64 {
            return Err(DecryptError);
        }
        let cert_signature = ed25519_dalek::Signature::from_bytes(nonce[0..64].try_into().unwrap());
        self.public_key
            .verify(&nonce[64..104], &cert_signature)
            .map_err(|_| DecryptError)?;
        let valid_after = NtpTimestamp::from_seconds_nanos_since_ntp_era(
            u32::from_be_bytes(nonce[96..100].try_into().unwrap()),
            0,
        );
        let valid_before = NtpTimestamp::from_seconds_nanos_since_ntp_era(
            u32::from_be_bytes(nonce[100..104].try_into().unwrap()),
            0,
        );
        if transmit_timestamp <= valid_after || transmit_timestamp >= valid_before {
            return Err(DecryptError);
        }
        let short_term_key =
            ed25519_dalek::VerifyingKey::from_bytes(nonce[64..96].try_into().unwrap())
                .map_err(|_| DecryptError)?;
        let message_signature =
            ed25519_dalek::Signature::from_bytes(ciphertext[0..64].try_into().unwrap());
        short_term_key
            .verify(associated_data, &message_signature)
            .map_err(|_| DecryptError)?;
        Ok(vec![])
    }

    fn key_bytes(&self) -> &[u8] {
        todo!()
    }
}

#[derive(Clone)]
pub struct Ed25519Private {
    certificate: Vec<u8>,
    short_term_key: ed25519_dalek::SecretKey,
}

impl Ed25519Private {
    pub fn new(
        short_term_key: [u8; ed25519_dalek::SECRET_KEY_LENGTH],
        certificate: Vec<u8>,
    ) -> Self {
        Ed25519Private {
            certificate,
            short_term_key,
        }
    }
}

impl ZeroizeOnDrop for Ed25519Private {}

impl Drop for Ed25519Private {
    fn drop(&mut self) {
        self.certificate.zeroize();
        self.short_term_key.zeroize();
    }
}

impl Cipher for Ed25519Private {
    fn etype(&self) -> CipherType {
        CipherType::Ed25519
    }

    fn encrypt(
        &self,
        buffer: &mut [u8],
        plaintext_length: usize,
        associated_data: &[u8],
    ) -> std::io::Result<EncryptResult> {
        if plaintext_length != 0 {
            return Err(std::io::ErrorKind::Other.into());
        }
        let mut cursor = std::io::Cursor::new(buffer);
        cursor.write_all(&self.certificate)?;

        let signer = ed25519_dalek::SigningKey::from_bytes(&self.short_term_key);
        let signature = signer.sign(associated_data);
        cursor.write_all(&signature.to_bytes())?;

        Ok(EncryptResult {
            nonce_length: self.certificate.len(),
            ciphertext_length: 64,
        })
    }

    fn decrypt(
        &self,
        _nonce: &[u8],
        _ciphertext: &[u8],
        _associated_data: &[u8],
        _transmit_timestamp: NtpTimestamp,
    ) -> Result<Vec<u8>, DecryptError> {
        // We don't support verification with the private key
        Err(DecryptError)
    }

    fn key_bytes(&self) -> &[u8] {
        todo!()
    }
}

impl std::fmt::Debug for Ed25519Private {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519Private")
            .field("certificate", &self.certificate)
            .finish()
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
    fn etype(&self) -> CipherType {
        CipherType::Nts
    }

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
        _transmit_timestamp: NtpTimestamp,
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
    use rand::SeedableRng;

    use super::*;

    #[test]
    fn test_ed25519() {
        let mut csprng = rand::rngs::StdRng::seed_from_u64(0);
        let long_term_key = ed25519_dalek::SigningKey::generate(&mut csprng);

        let short_term_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let mut certificate_data = vec![];
        certificate_data.extend_from_slice(&short_term_key.verifying_key().to_bytes());
        certificate_data.extend_from_slice(&3600u32.to_be_bytes());
        certificate_data.extend_from_slice(&7200u32.to_be_bytes());

        let cert_signature = long_term_key.sign(&certificate_data);
        let mut certificate = vec![];
        certificate.extend_from_slice(&cert_signature.to_bytes());
        certificate.extend_from_slice(&certificate_data);

        let privkey = Ed25519Private {
            certificate,
            short_term_key: short_term_key.to_bytes(),
        };

        let pubkey = Ed25519Public {
            public_key: long_term_key.verifying_key(),
        };

        let testdata = [0, 1, 2, 3, 4, 5, 6, 7];

        let mut buffer = [0; 168];

        assert!(privkey.encrypt(&mut buffer, 0, &testdata).is_ok());

        assert!(pubkey
            .decrypt(
                &buffer[0..104],
                &buffer[104..168],
                &testdata,
                NtpTimestamp::from_seconds_nanos_since_ntp_era(1000, 512327)
            )
            .is_err());
        assert!(pubkey
            .decrypt(
                &buffer[0..104],
                &buffer[104..168],
                &testdata,
                NtpTimestamp::from_seconds_nanos_since_ntp_era(6000, 512327)
            )
            .is_ok());
        assert!(pubkey
            .decrypt(
                &buffer[0..104],
                &buffer[104..168],
                &testdata,
                NtpTimestamp::from_seconds_nanos_since_ntp_era(8000, 512327)
            )
            .is_err());
    }

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
                NtpTimestamp::default(),
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
        assert!(key
            .decrypt(
                &testvec[..nonce_length],
                &testvec[nonce_length..(nonce_length + ciphertext_length)],
                &[2],
                NtpTimestamp::default(),
            )
            .is_err());
        let result = key
            .decrypt(
                &testvec[..nonce_length],
                &testvec[nonce_length..(nonce_length + ciphertext_length)],
                &[1],
                NtpTimestamp::default(),
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
                NtpTimestamp::default(),
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
        assert!(key
            .decrypt(
                &testvec[..nonce_length],
                &testvec[nonce_length..(nonce_length + ciphertext_length)],
                &[2],
                NtpTimestamp::default(),
            )
            .is_err());
        let result = key
            .decrypt(
                &testvec[..nonce_length],
                &testvec[nonce_length..(nonce_length + ciphertext_length)],
                &[1],
                NtpTimestamp::default(),
            )
            .unwrap();
        assert_eq!(result, (0..16).collect::<Vec<u8>>());
    }
}
