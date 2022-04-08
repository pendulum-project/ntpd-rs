mod clock;
mod packet;
mod time_types;

pub use clock::{NtpClock, SystemClock};
pub use packet::NtpHeader;
pub use time_types::{NtpDuration, NtpTimestamp};
