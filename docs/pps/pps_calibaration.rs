use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::os::unix::io::{AsRawFd, RawFd};
use std::mem::MaybeUninit;
use libc::{timespec, clock_gettime, CLOCK_REALTIME};
use std::io::{self, Result};
use chrono::{DateTime, NaiveDateTime, Utc};

pub struct PpsCalibration {
    pps_offset: Duration,
}

impl PpsCalibration {
    
    // Create a new instance of PpsCalibration with an initial offset of zero
    pub fn new() -> Self {
        PpsCalibration {
            pps_offset: Duration::from_secs(0),
        }
    }

    // Method to calculate the PPS offset
    pub fn calculate_offset(&mut self, gps_time: SystemTime) -> Result<()> {
        // Get the current time from the PPS signal
        let mut ts = MaybeUninit::<timespec>::uninit();

        unsafe {
            if clock_gettime(CLOCK_REALTIME, ts.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        let ts = unsafe { ts.assume_init() };
        let pps_time = UNIX_EPOCH + Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32);

        // Calculate the offset as the difference between GPS time and PPS time
        self.pps_offset = match gps_time.duration_since(pps_time) {
            Ok(duration) => duration,
            Err(e) => {
                Duration::from_secs(0)
            }
        };
        
        Ok(())
    }

    // Apply the offset to a given PPS timestamp
    pub fn apply_offset(&self, timestamp: SystemTime) -> SystemTime {
        timestamp + self.pps_offset
    }

}
