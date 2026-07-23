const RINGBUFFER_SIZE: usize = 8;

#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct UnorderedRingBuffer {
    values: [f64; RINGBUFFER_SIZE],
    n_values: usize,
    write_idx: usize,
}

impl UnorderedRingBuffer {
    pub(crate) fn insert(&mut self, value: f64) {
        self.values[self.write_idx] = value;
        self.write_idx = (self.write_idx + 1) % RINGBUFFER_SIZE;
        self.n_values = (self.n_values + 1).min(RINGBUFFER_SIZE);
    }
}

impl AsRef<[f64]> for UnorderedRingBuffer {
    fn as_ref(&self) -> &[f64] {
        &self.values[..self.n_values]
    }
}
