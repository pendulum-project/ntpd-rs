mod clock;
mod packet;
mod timetypes;

pub use packet::NtpHeader;
pub use timetypes::{NtpDuration, NtpTimestamp};
