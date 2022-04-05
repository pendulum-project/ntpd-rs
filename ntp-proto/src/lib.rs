mod clock;
mod packet;
mod timetypes;

pub use clock::{NtpClock, SystemClock};
pub use packet::NtpHeader;
pub use timetypes::{NtpDuration, NtpTimestamp};
