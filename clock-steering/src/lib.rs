//! Logic for steering OS clocks, aimed at NTP and PTP.
//!
//! This code is used in our implementations of NTP [ntpd-rs](https://github.com/pendulum-project/ntpd-rs) and PTP [statime](https://github.com/pendulum-project/statime).

#[cfg(target_os = "linux")]
mod linux_ioctls;

/// Low-level access to unix clocks.
#[cfg(unix)]
pub mod unix;
