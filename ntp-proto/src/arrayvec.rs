use std::io::Cursor;

pub struct ArrayVec<const N: usize> {
    buf: Cursor<[u8; N]>,
}

impl<const N: usize> Default for ArrayVec<N> {
    fn default() -> Self {
        Self {
            buf: Cursor::new([0; N]),
        }
    }
}

impl<const N: usize> ArrayVec<N> {
    pub fn as_slice(&self) -> &[u8] {
        <Self as AsRef<[u8]>>::as_ref(self)
    }

    pub fn capacity(&self) -> usize {
        N
    }
}

impl<const N: usize> std::io::Write for ArrayVec<N> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.write(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.buf.write_all(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.buf.flush()
    }
}

impl<const N: usize> AsRef<[u8]> for ArrayVec<N> {
    fn as_ref(&self) -> &[u8] {
        let len = self.buf.position() as usize;
        &self.buf.get_ref()[..len]
    }
}

impl<const N: usize> AsMut<[u8]> for ArrayVec<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        let len = self.buf.position() as usize;
        &mut self.buf.get_mut()[..len]
    }
}
