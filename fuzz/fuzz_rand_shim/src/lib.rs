//! This crate is a shim for the rand crate allowing deterministic testing for code otherwise using thread_rng
//! Note that it will only work properly for single-threaded tests, although multiple tests can be run in parallel
//! Also, for obvious reasons this is not safe to use in production.

use std::cell::RefCell;
use std::ops::DerefMut;

use real_rand::rngs::StdRng;

pub use real_rand::distributions;
pub use real_rand::prelude;
pub use real_rand::rngs;
pub use real_rand::seq;

pub use real_rand::{random, CryptoRng, Error, Fill, Rng, RngCore, SeedableRng};

thread_local!(
    static THREAD_RNG: RefCell<StdRng> = {
        RefCell::new(StdRng::seed_from_u64(0))
    }
);

pub fn thread_rng() -> real_rand::rngs::StdRng {
    THREAD_RNG
        .with(|t| StdRng::from_rng(t.borrow_mut().deref_mut()))
        .unwrap()
}

pub fn set_thread_rng(rng: StdRng) {
    THREAD_RNG.with(|t| *t.borrow_mut() = rng);
}
