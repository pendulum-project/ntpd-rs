use std::os::unix::io::{AsRawFd, RawFd};
use std::io::{Error, Result};
use std::fs::File;
use std::mem::MaybeUninit;
use libc::{self, timespec, clock_gettime, CLOCK_REALTIME};
use chrono::{NaiveDateTime, NaiveTimeZone, Utc};

fn get_pps_time(fd: RawFd) -> Result<(), Error> {
    let mut ts = MaybeUninit::<timespec>::uninit();

    unsafe {
        if clock_gettime(CLOCK_REALTIME, ts.as_mut_ptr()) != 0 {
            return Err(Error::last_os_error());
        }
    }

    let ts = unsafe { ts.assume_init() };
    let timestamp = ts.tv_sec as f64 + ts.tv_nsec as f64 / 1_000_000_000.0;

    // Convert Unix timestamp to NaiveDateTime
    let naive_datetime = NaiveDateTime::from_timestamp(timestamp as i64, (timestamp.fract() * 1_000_000_000.0) as u32);

    // Convert NaiveDateTime to Utc
    let utc_datetime = NaiveTimeZone::from_utc_datetime(&Utc, &naive_datetime);

    println!("Current UTC time: {}", utc_datetime);

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

