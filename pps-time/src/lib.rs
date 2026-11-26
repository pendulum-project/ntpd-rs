use std::{
    fs::File,
    io::{Error, Result},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, RawFd},
        raw::{c_uint, c_ulong},
    },
    path::Path,
};

pub mod pps;
use pps::{PPS_TIME_INVALID, pps_fdata, pps_kparams, pps_ktime};

// These constants rely on macros which bindgen does not export from pps.h
const PPS_GETPARAMS: c_ulong = 0x800870a1;
const PPS_SETPARAMS: c_ulong = 0x400870a2;
const PPS_GETCAP: c_ulong = 0x800870a3;
const PPS_FETCH: c_ulong = 0xc00870a4;

pub struct PpsDevice(File);

impl PpsDevice {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<PpsDevice> {
        Ok(PpsDevice(File::open(path)?))
    }

    /// Perform ioctl request and check result for possible errors
    unsafe fn ioctl<T>(&self, request: c_ulong, value: &mut T) -> Result<()> {
        match unsafe { libc::ioctl(self.0.as_raw_fd(), request as _, value) } {
            0 => Ok(()),
            _ => Err(Error::last_os_error()),
        }
    }

    /// Perform ioctl request with uninitialized memory
    unsafe fn ioctl_uninit<T>(&self, request: c_ulong) -> Result<T> {
        let mut value: MaybeUninit<T> = MaybeUninit::uninit();
        unsafe { self.ioctl(request, &mut value) }?;
        Ok(unsafe { value.assume_init() })
    }

    pub fn get_params(&self) -> Result<pps_kparams> {
        // Safety: PPS_GETPARAMS writes pps_kparams, for which memory is allocated and returned by ioctl_uninit
        unsafe { self.ioctl_uninit(PPS_GETPARAMS) }
    }

    pub fn set_params(&self, params: &mut pps_kparams) -> Result<()> {
        // Safety: PPS_SETPARAMS expects pps_kparams, which lives for the duration of the call
        unsafe { self.ioctl(PPS_SETPARAMS, params) }
    }

    pub fn get_cap(&self) -> Result<c_uint> {
        // Safety: PPS_GETCAP writes a c_uint, for which memory is allocated and returned by ioctl_uninit
        unsafe { self.ioctl_uninit(PPS_GETCAP) }
    }

    fn fetch(&self, timeout: pps_ktime) -> Result<pps_fdata> {
        let mut data = pps_fdata {
            info: Default::default(),
            timeout,
        };

        // Safety: PPS_FETCH expects and writes to a pps_fdata, which lives for the duration of the call
        unsafe { self.ioctl(PPS_FETCH, &mut data)? };

        Ok(data)
    }

    /// Fetch next PPS event, blocking until it arrives
    ///
    /// Device must support PPS_CANWAIT, otherwise it will give an EOPNOTSUPP error
    pub fn fetch_blocking(&self) -> Result<pps_fdata> {
        self.fetch(pps_ktime {
            sec: 0,
            nsec: 0,
            flags: PPS_TIME_INVALID,
        })
    }

    /// Fetch next PPS event with a timeout, giving an ETIMEDOUT error if event does not come in time
    ///
    /// Device must support PPS_CANWAIT, otherwise it will give an EOPNOTSUPP error
    pub fn fetch_timeout(&self, seconds: i64, nanoseconds: i32) -> Result<pps_fdata> {
        self.fetch(pps_ktime {
            sec: seconds,
            nsec: nanoseconds,
            flags: 0,
        })
    }

    /// Fetch newest PPS event without blocking
    pub fn fetch_non_blocking(&self) -> Result<pps_fdata> {
        self.fetch(pps_ktime {
            sec: 0,
            nsec: 0,
            flags: 0,
        })
    }
}

impl AsRawFd for PpsDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
