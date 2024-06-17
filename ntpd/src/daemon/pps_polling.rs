use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};
use std::mem::MaybeUninit;
use libc::{timespec, clock_gettime, CLOCK_REALTIME};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::io;
use chrono::{NaiveDateTime, DateTime, Utc};

#[derive(Debug)]
pub struct Pps {
    fd: RawFd,
    last_ntp_timestamp: NtpTimestamp,
}

impl Pps {
    pub fn new(path: &str) -> io::Result<Self> {
        let file = File::open(path)?;
        let fd = file.as_raw_fd();
        Ok(Pps {
            fd,
            last_ntp_timestamp: NtpTimestamp::from_unix_timestamp1(0),
        })
    }

    pub fn get_pps_time(&mut self) -> io::Result<(Duration, NtpTimestamp)> {
        let mut ts = MaybeUninit::<timespec>::uninit();
        unsafe {
            if clock_gettime(CLOCK_REALTIME, ts.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        let ts = unsafe { ts.assume_init() };
        let timestamp = ts.tv_sec as u64;
        let nanos = ts.tv_nsec as u32;

        let ntp_timestamp = NtpTimestamp::from_unix_timestamp(timestamp, nanos);
        let time_diff = ntp_timestamp - self.last_ntp_timestamp;
        self.last_ntp_timestamp = ntp_timestamp;

        let duration_since_epoch = Duration::new(timestamp, nanos);
        Ok((duration_since_epoch, ntp_timestamp))
    }

    pub fn readable_time(&self, duration_since_epoch: Duration) -> String {
        let timestamp = duration_since_epoch.as_secs() as i64;
        let nanos = duration_since_epoch.subsec_nanos();
        let naive_datetime = NaiveDateTime::from_timestamp(timestamp, nanos);
        let datetime: DateTime<Utc> = DateTime::from_utc(naive_datetime, Utc);
        datetime.to_string()
    }
}

// use std::mem::MaybeUninit;
// use std::os::unix::io::RawFd;
// use libc::{timespec, clock_gettime, CLOCK_REALTIME};
// use std::io;
// use ntp_proto::NtpTimestamp;

// /// Gets the PPS time and returns it as an NtpTimestamp.
// ///
// /// # Arguments
// ///
// /// * `fd` - The file descriptor for the PPS device.
// ///
// /// # Returns
// ///
// /// * `Result<NtpTimestamp, String>` - The result of getting the PPS time.
// pub async fn poll_pps_signal(fd: RawFd) -> Result<NtpTimestamp, String> {
//     let mut ts = MaybeUninit::<timespec>::uninit();
//     unsafe {
//         if clock_gettime(CLOCK_REALTIME, ts.as_mut_ptr()) != 0 {
//             return Err(io::Error::last_os_error().to_string());
//         }
//     }

//     let ts = unsafe { ts.assume_init() };
//     let timestamp = ts.tv_sec as u64;
//     let nanos = ts.tv_nsec as u32;

//     let ntp_timestamp = from_unix_timestamp(timestamp, nanos);

//     Ok(ntp_timestamp)
// }

// #[derive(Debug)]
// pub enum AcceptResult {
//     Accept(NtpTimestamp),
//     Ignore,
// }

// pub fn accept_pps_time(result: Result<NtpTimestamp, String>) -> AcceptResult {
//     match result {
//         Ok(timestamp) => AcceptResult::Accept(timestamp),
//         Err(receive_error) => {
//             warn!(?receive_error, "could not receive PPS signal");
//             AcceptResult::Ignore
//         }
//     }
// }
