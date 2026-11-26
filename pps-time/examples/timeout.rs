// FIXME: Remove this or make them target the more specific parts of the crate.
#![expect(missing_docs)]
#![expect(clippy::cast_possible_wrap)]

use pps_time::{PpsDevice, pps};
use std::path::PathBuf;

/// A simple PPS demo program
///
/// Build with `cargo build --package pps-time --example timeout`
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Example usage:");
        println!("$ sudo ./target/debug/examples/timeout /dev/pps0");
        return;
    }

    let path = PathBuf::from(&args[1]); // path to PPS device

    println!("Opening PPS device {}", path.display());
    let pps = PpsDevice::new(path).expect("Could not open file!");

    let capabilities = pps.get_cap().expect("Could not get capabilities!");
    println!("Capabilities: {:#x}", capabilities);

    let mut params = pps.get_params().expect("Could not get params!");
    println!("{:?}", params);

    // Turn on CAPTUREASSERT if available
    if capabilities & pps::PPS_CAPTUREASSERT != 0 {
        params.mode |= pps::PPS_CAPTUREASSERT as i32;
    } else {
        println!("Cannot CAPTUREASSERT");
    }
    // Turn on CAPTURECLEAR if available
    if capabilities & pps::PPS_CAPTURECLEAR != 0 {
        params.mode |= pps::PPS_CAPTURECLEAR as i32;
    } else {
        println!("Cannot CAPTURECLEAR");
    }

    pps.set_params(&mut params).expect("Could not set params!");

    loop {
        let data = pps.fetch_timeout(0, 500_000_000);
        println!("{:#?}", data); // half of these should be timeouts for 1PPS devices
    }
}
