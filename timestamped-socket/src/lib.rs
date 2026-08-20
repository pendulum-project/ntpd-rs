//! A library for networking with timestamping support.

use statime_base::Timestamp;

mod control_message;
/// Types and operations for finding and manipulating network interfaces.
pub mod interface;
/// Traits and types related to network addresses.
pub mod networkaddress;
mod raw_socket;
/// Types and operations related to sockets.
pub mod socket;

/// Turn a C failure (-1 is returned) into a rust Result
pub(crate) fn cerr(t: libc::c_int) -> std::io::Result<libc::c_int> {
    match t {
        -1 => Err(std::io::Error::last_os_error()),
        _ => Ok(t),
    }
}

/// Convert a timespec struct to a timestamp.
#[cfg_attr(target_os = "macos", allow(unused))]
#[expect(
    clippy::cast_sign_loss,
    reason = "tv_usec is always in range for the nanos field."
)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "tv_usec is always in range for the conversion."
)]
#[allow(
    clippy::cast_lossless,
    reason = "cast is not lossless on all platforms."
)]
fn timestamp_from_timespec<T>(timespec: libc::timespec) -> Timestamp<T> {
    Timestamp::from_seconds_nanos_since_unix_epoch(timespec.tv_sec as _, timespec.tv_nsec as _)
}

/// Convert a timeval struct to a timestamp
#[expect(
    clippy::cast_sign_loss,
    reason = "tv_usec is always in range for the nanos field."
)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "tv_usec is always in range for the conversion."
)]
#[allow(
    clippy::cast_lossless,
    reason = "cast is not lossless on all platforms."
)]
fn timestamp_from_timeval<T>(timeval: libc::timeval) -> Timestamp<T> {
    Timestamp::from_seconds_nanos_since_unix_epoch(
        timeval.tv_sec as _,
        (timeval.tv_usec * 1000) as _,
    )
}
