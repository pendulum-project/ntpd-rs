use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;
use libc::{timespec, clock_gettime, CLOCK_REALTIME};
use std::io;
use ntp_proto::NtpTimestamp;

/// Gets the PPS time and returns it as an NtpTimestamp.
///
/// # Arguments
///
/// * `fd` - The file descriptor for the PPS device.
///
/// # Returns
///
/// * `Result<NtpTimestamp, String>` - The result of getting the PPS time.
pub async fn poll_pps_signal(fd: RawFd) -> Result<NtpTimestamp, String> {
    let mut ts = MaybeUninit::<timespec>::uninit();
    unsafe {
        if clock_gettime(CLOCK_REALTIME, ts.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error().to_string());
        }
    }

    let ts = unsafe { ts.assume_init() };
    let timestamp = ts.tv_sec as u64;
    let nanos = ts.tv_nsec as u32;

    let ntp_timestamp = from_unix_timestamp(timestamp, nanos);

    Ok(ntp_timestamp)
}

#[derive(Debug)]
pub enum AcceptResult {
    Accept(NtpTimestamp),
    Ignore,
}

pub fn accept_pps_time(result: Result<NtpTimestamp, String>) -> AcceptResult {
    match result {
        Ok(timestamp) => AcceptResult::Accept(timestamp),
        Err(receive_error) => {
            warn!(?receive_error, "could not receive PPS signal");
            AcceptResult::Ignore
        }
    }
}

