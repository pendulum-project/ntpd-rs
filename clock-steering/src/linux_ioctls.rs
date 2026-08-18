//! Linux ioctl definitions for PTP clock devices.
//!
//! These definitions are derived from <linux/ptp_clock.h>.

use std::os::unix::io::RawFd;

/// PTP clock capabilities as reported by the kernel.
#[repr(C)]
pub struct PtpClockCaps {
    pub max_adj: libc::c_int, // Maximum frequency adjustment in parts per billion
    pub n_alarm: libc::c_int, // Number of programmable alarms
    pub n_ext_ts: libc::c_int, // Number of external time stamp channels
    pub n_per_out: libc::c_int, // Number of programmable periodic signals
    pub pps: libc::c_int,     // Whether the clock supports a PPS callback
    pub n_pins: libc::c_int,  // Number of input/output pins
    pub cross_timestamping: libc::c_int, // Whether the clock supports precise system-device cross timestamps
    pub adjust_phase: libc::c_int,       // Whether the clock supports adjust phase
    pub max_phase_adj: libc::c_int,      // Maximum offset adjustment in nanoseconds
    pub rsv: [libc::c_int; 11],          // Reserved for future use
}

// PTP_CLOCK_GETCAPS = _IOR('=', 1, struct ptp_clock_caps)
//
// Linux _IOR encoding: (IOC_READ << 30) | (size << 16) | (type << 8) | nr
//   IOC_READ = 2, type = b'=' = 0x3D, nr = 1
const PTP_CLOCK_GETCAPS: u32 =
    (2u32 << 30) | ((std::mem::size_of::<PtpClockCaps>() as u32) << 16) | ((b'=' as u32) << 8) | 1;

/// Query PTP clock capabilities via ioctl.
///
/// Returns 0 on success, -1 on error (check `errno` for details).
///
/// # Safety
/// `caps` must be a valid, writable pointer to a `PtpClockCaps`.
pub unsafe fn ptp_clock_getcaps(fd: RawFd, caps: *mut PtpClockCaps) -> libc::c_int {
    libc::ioctl(fd, PTP_CLOCK_GETCAPS as _, caps)
}
