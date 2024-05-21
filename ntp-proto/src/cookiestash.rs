/// Datastructure for managing cookies. It keeps the following
/// invariants:
///   - Each cookie is yielded at most once
///   - The oldest cookie is always yielded first
/// Note that as a consequence, this type is not Clone!
#[derive(Default, PartialEq, Eq)]
pub(crate) struct CookieStash {
    cookies: [Vec<u8>; 8],
    read: usize,
    valid: usize,
}

impl std::fmt::Debug for CookieStash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieStash")
            .field("cookies", &self.cookies.len())
            .field("read", &self.read)
            .field("valid", &self.valid)
            .finish()
    }
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
        assert_eq!(stash.get(), None);
    }

    #[test]
    fn test_overfill() {
        let mut stash = CookieStash::default();
        for i in 0..10_u8 {
            stash.store(vec![i]);
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
