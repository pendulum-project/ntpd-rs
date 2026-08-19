//! Demonstrates the clock-steering library.
//!
//! Usage: cargo run --example basic [realtime|tai|/dev/ptpN]
//!
//! Write operations (frequency, step, leap seconds, TAI) require root privileges.

use clock_steering::unix::UnixClock;
use statime_base::{Clock, Duration, LeapStatus, Timestamp};

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
    let nanos = (now - Timestamp::UNIX_EPOCH).as_nanos();
    let seconds = nanos / 1_000_000_000;
    let nanos = nanos % 1_000_000_000;
    println!("now:         {}.{:09}", seconds, nanos);

    let res = clock.resolution()?;
    println!("resolution:  {}ns", res.as_nanos());

    let max_freq = clock.max_frequency()?;
    println!("max freq:    {} ppm", max_freq * 1e6);

    match clock.get_frequency() {
        Ok(f) => println!("frequency:   {:.6} us/s", f * 1e6),
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
        Ok(t) => println!(
            "set_frequency(0.0):     ok at {}.{:09}",
            (t - Timestamp::UNIX_EPOCH).as_nanos() / 1_000_000_000,
            (t - Timestamp::UNIX_EPOCH).as_nanos() % 1_000_000_000
        ),
        Err(e) => println!("set_frequency(0.0):     {e}"),
    }

    match clock.step_clock(Duration::from_seconds_nanos(0, 0)) {
        Ok(t) => println!(
            "step_clock(0):          ok at {}.{:09}",
            (t - Timestamp::UNIX_EPOCH).as_nanos() / 1_000_000_000,
            (t - Timestamp::UNIX_EPOCH).as_nanos() % 1_000_000_000
        ),
        Err(e) => println!("step_clock(0):          {e}"),
    }

    match clock.leap_update(LeapStatus::None) {
        Ok(()) => println!("set_leap_seconds:       ok"),
        Err(e) => println!("set_leap_seconds:       {e}"),
    }

    match clock.error_estimate_update(
        Duration::from_seconds_nanos(0, 100_000),
        Duration::from_seconds_nanos(0, 1_000_000),
    ) {
        Ok(()) => println!("error_estimate_update:  ok"),
        Err(e) => println!("error_estimate_update:  {e}"),
    }

    match clock.disable_kernel() {
        Ok(()) => println!("disable_kernel_ntp:     ok"),
        Err(e) => println!("disable_kernel_ntp:     {e}"),
    }

    Ok(())
}
