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
            let mut result = vec![];
            std::mem::swap(&mut result, &mut self.cookies[self.read]);
            self.read = (self.read + 1) % self.cookies.len();
            self.valid -= 1;
            Some(result)
        }
    }

    /// Number of cookies missing from the stash
    pub fn gap(&self) -> usize {
        self.cookies.len() - self.valid
    }

    pub fn is_empty(&self) -> bool {
        self.valid == 0
    }
}

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
            assert_eq!(stash.gap(), 7 - (i as usize));
        }

        for i in 8_u8..32_u8 {
            assert_eq!(stash.get(), Some(vec![i - 8]));
            assert_eq!(stash.gap(), 1);
            stash.store(vec![i]);
            assert_eq!(stash.gap(), 0);
        }
    }
}
