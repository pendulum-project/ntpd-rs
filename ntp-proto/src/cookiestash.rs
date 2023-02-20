use std::borrow::Cow;

use crate::nts_record::AeadAlgorithm;

/// Datastructure for managing cookies. It keeps the following
/// invariants:
///   - Each cookie is yielded at most once
///   - The oldest cookie is always yielded first
/// Note that as a consequence, this type is not Clone!
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct CookieStash {
    cookies: [Vec<u8>; 8],
    read: usize,
    valid: usize,
}

impl CookieStash {
    /// Store a new cookie
    pub fn store(&mut self, cookie: Vec<u8>) {
        let wpos = (self.read + self.valid) % self.cookies.len();
        self.cookies[wpos] = cookie;
        if self.valid < self.cookies.len() {
            self.valid += 1;
        } else {
            debug_assert!(self.valid == self.cookies.len());
            // No place for extra cookies, but it is still
            // newer so just keep the newest cookies.
            self.read = (self.read + 1) % self.cookies.len();
        }
    }

    /// Get oldest cookie
    pub fn get(&mut self) -> Option<Vec<u8>> {
        if self.valid == 0 {
            None
        } else {
            // takes the cookie, puts `vec![]` in its place
            let result = std::mem::take(&mut self.cookies[self.read]);
            self.read = (self.read + 1) % self.cookies.len();
            self.valid -= 1;
            Some(result)
        }
    }

    /// Number of cookies missing from the stash
    pub fn gap(&self) -> u8 {
        // This never overflows or underflows since cookies.len will
        // fit in a u8 and 0 <= self.valid <= self.cookies.len()
        (self.cookies.len() - self.valid) as u8
    }

    pub fn is_empty(&self) -> bool {
        self.valid == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_read() {
        let mut stash = CookieStash::default();
        assert_eq!(stash.get(), None)
    }

    #[test]
    fn test_overfill() {
        let mut stash = CookieStash::default();
        for i in 0..10_u8 {
            stash.store(vec![i])
        }
        assert_eq!(stash.get(), Some(vec![2]));
        assert_eq!(stash.get(), Some(vec![3]));
    }

    #[test]
    fn test_normal_op() {
        let mut stash = CookieStash::default();
        for i in 0..8_u8 {
            stash.store(vec![i]);
            assert_eq!(stash.gap(), 7 - i);
        }

        for i in 8_u8..32_u8 {
            assert_eq!(stash.get(), Some(vec![i - 8]));
            assert_eq!(stash.gap(), 1);
            stash.store(vec![i]);
            assert_eq!(stash.gap(), 0);
        }
    }
}

pub(crate) struct Cookie(Vec<u8>);

impl Cookie {
    pub fn new<C: crate::Cipher + ?Sized>(
        server_key: &C,
        identifier: u32,
        algorithm: AeadAlgorithm,
        s2c: &[u8],
        c2s: &[u8],
    ) -> std::io::Result<Self> {
        debug_assert_eq!(c2s.len(), s2c.len());
        let mut plaintext = Vec::with_capacity(2 + s2c.len() + c2s.len());

        plaintext.extend((algorithm as u16).to_be_bytes());
        plaintext.extend(s2c);
        plaintext.extend(c2s);

        Self::new_from_plaintext(server_key, identifier, plaintext)
    }

    fn new_from_plaintext<C: crate::Cipher + ?Sized>(
        server_key: &C,
        identifier: u32,
        mut plaintext: Vec<u8>,
    ) -> std::io::Result<Self> {
        // form AEAD output 'C' by encrypting 'P' under key 'K' with nonce 'N' and no associated data.
        let encrypted = server_key.encrypt(plaintext.as_slice(), &[])?;

        plaintext.clear();

        let mut output = plaintext;

        output.extend(identifier.to_be_bytes());
        output.extend(encrypted.nonce);
        output.extend(encrypted.ciphertext);

        Ok(Cookie(output))
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    fn plaintext<'a, F, K>(&self, identifier_to_key: F) -> Option<(&'a K, u32, Vec<u8>)>
    where
        F: FnOnce(u32) -> &'a K,
        K: crate::Cipher + ?Sized + 'a,
    {
        // 4 bytes for the identifier, 16 for the nonce, at least 16 for the ciphertext
        if self.0.len() < 4 + 16 + 16 {
            tracing::error!("cookie bytes are too short");
            return None;
        }

        let identifier = u32::from_be_bytes(self.0[0..][..4].try_into().unwrap());
        let (nonce, ciphertext) = self.0[4..].split_at(16);

        let server_key = identifier_to_key(identifier);
        let plaintext = server_key.decrypt(nonce.into(), ciphertext, &[]).ok()?;

        // 2 bytes for algorithm, s2c and c2s
        if plaintext.len() != 2 + 2 * server_key.key_width() {
            tracing::error!("plaintext has incorect size");
            return None;
        }

        Some((server_key, identifier, plaintext))
    }

    fn generate_next<'a, F, K>(&self, identifier_to_key: F) -> std::io::Result<Self>
    where
        F: FnOnce(u32) -> &'a K,
        K: crate::Cipher + ?Sized + 'a,
    {
        let (server_key, identifier, plaintext) = match self.plaintext(identifier_to_key) {
            Some(t) => t,
            None => {
                tracing::error!("Decoding the plaintext failed");
                return Err(std::io::Error::from(std::io::ErrorKind::Other));
            }
        };

        Self::new_from_plaintext(server_key, identifier, plaintext)
    }
}

#[cfg(test)]
mod tests2 {
    use crate::packet::AesSivCmac256;

    use super::*;

    #[test]
    fn roundtrip() {
        let server_key: Box<dyn crate::Cipher> = Box::new(AesSivCmac256::new([0; 32].into()));
        let identifier = 42u32;
        let algorithm = AeadAlgorithm::AeadAesSivCmac256;

        let s2c: Vec<u8> = (0..32).collect();
        let c2s: Vec<u8> = (0..32).rev().collect();

        let cookie = Cookie::new(server_key.as_ref(), identifier, algorithm, &s2c, &c2s).unwrap();

        let mut expected_plaintext = Vec::new();
        expected_plaintext.extend([0u8, 15]);
        expected_plaintext.extend(s2c);
        expected_plaintext.extend(c2s);

        let identifier_to_key = |id| match id {
            42 => server_key.as_ref(),
            _ => panic!("unknown server key identifier: {id}"),
        };

        let (_server_key, _identifier, actual_plaintext) =
            cookie.plaintext(identifier_to_key).unwrap();

        assert_eq!(actual_plaintext, expected_plaintext);
    }
}
