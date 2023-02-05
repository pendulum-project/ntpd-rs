#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SequenceIdGenerator {
    current: u16,
}

impl SequenceIdGenerator {
    pub fn new() -> Self {
        SequenceIdGenerator { current: 0 }
    }

    pub fn generate(&mut self) -> u16 {
        self.current = self.current.wrapping_add(1);
        self.current
    }
}
