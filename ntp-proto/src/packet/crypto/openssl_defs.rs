//! This file contains file types that mimic those in RustCrypto, so *at a source level* code sharing can be maximized.

use std::ops::Deref;

#[derive(Debug, Clone, Copy, Default)]
pub struct Aes128Siv;

#[derive(Debug, Clone, Copy, Default)]
pub struct Aes256Siv;

#[repr(transparent)]
pub struct Key<T>(<Key<T> as Deref>::Target)
where
    Key<T>: Deref;

impl Deref for Key<Aes128Siv> {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for Key<Aes256Siv> {
    type Target = [u8; 64];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for Key<Aes128Siv> {
    fn default() -> Self {
        Self([0; _])
    }
}

impl Default for Key<Aes256Siv> {
    fn default() -> Self {
        Self([0; _])
    }
}

impl<T> FromIterator<u8> for Key<T>
where
    Key<T>: Deref + Default,
    <Key<T> as Deref>::Target: AsMut<[u8]>,
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

impl<T> AsMut<[u8]> for Key<T>
where
    Key<T>: Deref,
    <Key<T> as Deref>::Target: AsMut<[u8]>,
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
