#[derive(Debug, Clone, Default)]
pub struct SequenceIdGenerator {
    cur_id: u16,
}

impl SequenceIdGenerator {
    pub fn generate(&mut self) -> u16 {
        self.cur_id = self.cur_id.wrapping_add(1);
        self.cur_id
    }
}
