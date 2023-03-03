//! A cursor wrapping an array for a quick and easy writable temporary buffer

use std::io::Cursor;

pub struct MemBuffer<const N: usize> {
    buf: Cursor<[u8; N]>,
}

impl<const N: usize> Default for MemBuffer<N> {
    fn default() -> Self {
        Self {
            buf: Cursor::new([0; N]),
        }
    }
}

impl<const N: usize> MemBuffer<N> {
    pub fn as_slice(&self) -> &[u8] {
        let len = self.buf.position() as usize;

        &self.buf.get_ref()[..len]
    }

    pub fn capacity(&self) -> usize {
        N
    }
}

impl<const N: usize> std::io::Write for MemBuffer<N> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.buf.flush()
    }
}
