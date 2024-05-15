use std::os::unix::io::{AsRawFd, RawFd};
use std::io::{Error, Result};
use std::fs::File;
use std::mem::MaybeUninit;
use libc::{self, timespec, clock_gettime, CLOCK_REALTIME};
use chrono::{NaiveDateTime, NaiveTimeZone, Utc};

// Define the NtpTimestamp struct and its implementation
#[derive(Debug)]
struct NtpTimestamp {
    timestamp: u64,
}

impl NtpTimestamp {
    pub const fn from_bits(bits: [u8; 8]) -> NtpTimestamp {
        NtpTimestamp {
            timestamp: u64::from_be_bytes(bits),
        }
    }

    pub const fn to_bits(self) -> [u8; 8] {
        self.timestamp.to_be_bytes()
    }
    /// Create an NTP timestamp from the number of seconds and nanoseconds that have
    /// passed since the last ntp era boundary.
    pub const fn from_seconds_nanos_since_ntp_era(seconds: u32, nanos: u32) -> Self {
        // Although having a valid interpretation, providing more
        // than 1 second worth of nanoseconds as input probably
        // indicates an error from the caller.        
        debug_assert!(nanos < 1_000_000_000);
        // NTP uses 1/2^32 sec as its unit of fractional time.
        // our time is in nanoseconds, so 1/1e9 seconds        
        let fraction = ((nanos as u64) << 32) / 1_000_000_000;

        // alternatively, abuse FP arithmetic to save an instruction
        // let fraction = (nanos as f64 * 4.294967296) as u64;        
        let timestamp = ((seconds as u64) << 32) + fraction;
        NtpTimestamp::from_bits(timestamp.to_be_bytes())
    }

    pub fn from_unix_timestamp(unix_timestamp: u64) -> Self {
        let system_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(unix_timestamp);
        let duration_since_epoch = system_time.duration_since(std::time::UNIX_EPOCH).unwrap();
        let seconds = duration_since_epoch.as_secs() as u32;
        let nanos = duration_since_epoch.subsec_nanos();
        NtpTimestamp::from_seconds_nanos_since_ntp_era(seconds, nanos)
    }
}

fn get_pps_time(fd: RawFd) -> Result<(), Error> {
    let mut ts = MaybeUninit::<timespec>::uninit();

    unsafe {
        if clock_gettime(CLOCK_REALTIME, ts.as_mut_ptr()) != 0 {
            return Err(Error::last_os_error());
        }
    }

    let ts = unsafe { ts.assume_init() };
    let timestamp = ts.tv_sec as u64;

    // Convert Unix timestamp to NtpTimestamp
    let ntp_timestamp = NtpTimestamp::from_unix_timestamp(timestamp);

    println!("Current NTP Timestamp: {:?}", ntp_timestamp);

    Ok(())
}


fn main() -> Result<(), Error> {
    let path = "/dev/pps0";
    let file = File::open(path)?;
    let fd = file.as_raw_fd();

    loop {
        get_pps_time(fd)?;
    }
}

