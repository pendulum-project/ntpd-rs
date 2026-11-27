pub struct Buffer<'a> {
    buffer: &'a mut [u8],
    valid: usize,
}

impl<'a> Buffer<'a> {
    pub fn new(buffer: &'a mut [u8], valid: usize) -> Self {
        Self { buffer, valid }
    }

    pub fn valid(&self) -> usize {
        self.valid
    }
}

impl AsMut<[u8]> for Buffer<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[..self.valid]
    }
}

impl AsRef<[u8]> for Buffer<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.valid]
    }
}

impl aead::Buffer for Buffer<'_> {
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
