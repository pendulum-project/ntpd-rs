#![forbid(unsafe_code)]

mod clock;
mod filter;
mod identifiers;
mod packet;
mod time_types;

pub use clock::NtpClock;
#[cfg(feature = "fuzz")]
pub use filter::fuzz_find_interval;
pub use identifiers::ReferenceId;
pub use packet::NtpHeader;
pub use time_types::{NtpDuration, NtpTimestamp};
