use std::os::unix::io::{AsRawFd, RawFd};
use std::io::Error;

fn get_pps_time(fd: RawFd) -> Result<(), Error> {
    let mut ts = timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        if clock_gettime(CLOCK_REALTIME, &mut ts) != 0 {
            return Err(Error::last_os_error());
        }
    }
    println!("Current time: {}.{}", ts.tv_sec, ts.tv_nsec);
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

