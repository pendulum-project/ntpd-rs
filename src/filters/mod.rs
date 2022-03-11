pub mod basic;

use crate::{port::Measurement, time::OffsetTime};

pub trait Filter {
    fn absorb(&mut self, m: Measurement) -> (OffsetTime, f64);
}
