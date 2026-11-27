//! This file contains file types that mimic those in RustCrypto, so *at a source level* code sharing can be maximized.

use std::io;
use std::ops::Deref;

#[derive(Debug, Clone, Copy, Default)]
pub struct Aes128Siv;

#[derive(Debug, Clone, Copy, Default)]
pub struct Aes256Siv;

pub trait EVPCipher {
    type Key: AsRef<[u8]> + AsMut<[u8]>;
    fn name() -> &'static str;
}

impl EVPCipher for Aes128Siv {
    type Key = [u8; 32];

    fn name() -> &'static str {
        "AES-128-SIV"
    }
}

impl EVPCipher for Aes256Siv {
    type Key = [u8; 64];

    fn name() -> &'static str {
        "AES-256-SIV"
    }
}

#[repr(transparent)]
pub struct Key<T: EVPCipher>(T::Key);

// The following is boilerplate or generic code

impl<T: EVPCipher> Deref for Key<T> {
    type Target = T::Key;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize, T: EVPCipher<Key = [u8; N]>> Default for Key<T> {
    fn default() -> Self {
        Self([0; _])
    }
}

impl<T: EVPCipher> FromIterator<u8> for Key<T>
where
    Self: Default,
{
    fn from_iter<I: IntoIterator<Item = u8>>(data: I) -> Self {
        let mut iter = data.into_iter();
        let mut new = Self::default();
        for elem in new.as_mut() {
            *elem = iter.next().expect("input data too short");
        }

        assert_eq!(iter.count(), 0, "input data too long");
        new
    }
}

impl<T: EVPCipher> AsMut<[u8]> for Key<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

#[cfg(test)]
impl<const N: usize, T: EVPCipher<Key = [u8; N]>> From<[u8; N]> for Key<T> {
    fn from(data: [u8; N]) -> Self {
        Self(data)
    }
}

// NOTE for future modifications: if AES-GCM-SIV is to be added, keep in mind lessons learned the hard way:
// - the tag is at the end of the ciphertext, whereas with AES-SIV it sits at the beginning
// - the nonce needs to be set using crypt_init as the IV and is not provided as associated data

pub fn decrypt_vec<T: EVPCipher>(
    key: &Key<T>,
    ciphertext: &[u8],
    aad: [&[u8]; 2],
) -> io::Result<Vec<u8>>
where
{
    let cipher = &openssl::cipher::Cipher::fetch(None, T::name(), None)?;
    let mut ctx = openssl::cipher_ctx::CipherCtx::new()?;

    ctx.decrypt_init(Some(cipher), Some(key.as_ref()), None)?;

    let (tag, ciphertext) = ciphertext
        .split_at_checked(ctx.tag_length())
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;

    let mut output = Vec::new();
    ctx.set_tag(tag)?;
    for aad_data in aad.into_iter() {
        ctx.cipher_update(aad_data, None)?;
    }
    ctx.cipher_update_vec(ciphertext, &mut output)?;
    ctx.cipher_final_vec(&mut output)?;

    Ok(output)
}

pub fn encrypt_in_place<T: EVPCipher>(
    key: &Key<T>,
    buffer: &mut [u8],
    plaintext_length: usize,
    aad: [&[u8]; 2],
) -> io::Result<usize>
where
{
    let cipher = &openssl::cipher::Cipher::fetch(None, T::name(), None)?;
    let mut ctx = openssl::cipher_ctx::CipherCtx::new()?;

    ctx.encrypt_init(Some(cipher), Some(key.as_ref()), None)?;

    // this is annoying since we're copying a second time; but it does make
    // the layer above more logical to follow
    if buffer.len() < plaintext_length + ctx.tag_length() {
        return Err(std::io::ErrorKind::WriteZero.into());
    }
    buffer.copy_within(..plaintext_length, ctx.tag_length());

    let (tag, ciphertext) = buffer.split_at_mut(ctx.tag_length());

    for aad_data in aad.into_iter() {
        ctx.cipher_update(aad_data, None)?;
    }
    let mut ciphertext_length = ctx.cipher_update_inplace(ciphertext, plaintext_length)?;
    ciphertext_length += ctx.cipher_final(&mut ciphertext[ciphertext_length..])?;

    ctx.tag(tag)?;

    Ok(ciphertext_length + tag.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_roundtrip() {
        let payload: [u8; 16] = std::array::from_fn(|i| i as u8);
        let mut buf = [0; 32];
        buf[..16].copy_from_slice(&payload);
        let key: Key<Aes128Siv> = Default::default();
        let size = encrypt_in_place(&key, &mut buf, 16, [&[1], &[2]]).unwrap();
        let ciphertext = &buf[..size];
        let plaintext = decrypt_vec(&key, ciphertext, [&[1], &[2]]).unwrap();
        assert_eq!(plaintext, payload);

        let mut buf = [0; 32];
        buf[..16].copy_from_slice(&payload);
        let key: Key<Aes256Siv> = Default::default();
        let size = encrypt_in_place(&key, &mut buf, 16, [&[1], &[2]]).unwrap();
        let ciphertext = &buf[..size];
        let plaintext = decrypt_vec(&key, ciphertext, [&[1], &[2]]).unwrap();
        assert_eq!(plaintext, payload);
    }
}
