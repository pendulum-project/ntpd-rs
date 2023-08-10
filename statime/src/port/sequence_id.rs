#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct SequenceIdGenerator {
    current: u16,
}

impl SequenceIdGenerator {
    pub(crate) fn new() -> Self {
        SequenceIdGenerator { current: 0 }
    }

    pub(crate) fn generate(&mut self) -> u16 {
        let id = self.current;
        self.current = self.current.wrapping_add(1);
        id
    }
}
