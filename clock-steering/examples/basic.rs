//! Demonstrates the clock-steering library.
//!
//! Usage: cargo run --example basic [realtime|tai|/dev/ptpN]
//!
//! Write operations (frequency, step, leap seconds, TAI) require root privileges.

use clock_steering::{unix::UnixClock, Clock, LeapIndicator, TimeOffset};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    let arg = std::env::args().nth(1);

    #[cfg(target_os = "linux")]
    let clock: UnixClock = match arg.as_deref() {
        None | Some("realtime") => UnixClock::CLOCK_REALTIME,
        Some("tai") => UnixClock::CLOCK_TAI,
        Some(path) if path.starts_with("/dev/") => UnixClock::open(path)?,
        Some(other) => {
            eprintln!("unknown clock: {other}");
            eprintln!("usage: basic [realtime|tai|/dev/ptpN]");
            std::process::exit(1);
        }
    };

    #[cfg(not(target_os = "linux"))]
    let clock = UnixClock::CLOCK_REALTIME;

    // Read-only operations

    let now = clock.now()?;
    println!("now:         {}.{:09}", now.seconds, now.nanos);

    let res = clock.resolution()?;
    println!("resolution:  {}ns", res.nanos);

    let caps = clock.capabilities()?;
    println!("max freq:    {} ppm", caps.max_frequency_adjustment_ppm);
    println!("max offset:  {}ns", caps.max_offset_adjustment_ns);

    match clock.get_frequency() {
        Ok(f) => println!("frequency:   {f:.6} ms/s"),
        Err(e) => println!("frequency:   {e}"),
    }

    #[cfg(target_os = "linux")]
    match clock.get_tai() {
        Ok(tai) => println!("TAI offset:  {tai}s"),
        Err(e) => println!("TAI offset:  {e}"),
    }

    // Write operations — require root

    println!();

    match clock.set_frequency(0.0) {
        Ok(t) => println!("set_frequency(0.0):     ok at {}.{:09}", t.seconds, t.nanos),
        Err(e) => println!("set_frequency(0.0):     {e}"),
    }

    match clock.step_clock(TimeOffset {
        seconds: 0,
        nanos: 0,
    }) {
        Ok(t) => println!("step_clock(0):          ok at {}.{:09}", t.seconds, t.nanos),
        Err(e) => println!("step_clock(0):          {e}"),
    }

    match clock.set_leap_seconds(LeapIndicator::NoWarning) {
        Ok(()) => println!("set_leap_seconds:       ok"),
        Err(e) => println!("set_leap_seconds:       {e}"),
    }

    match clock.error_estimate_update(Duration::from_micros(100), Duration::from_millis(1)) {
        Ok(()) => println!("error_estimate_update:  ok"),
        Err(e) => println!("error_estimate_update:  {e}"),
    }

    match clock.disable_kernel_ntp_algorithm() {
        Ok(()) => println!("disable_kernel_ntp:     ok"),
        Err(e) => println!("disable_kernel_ntp:     {e}"),
    }

    Ok(())
}
