#![forbid(unsafe_code)]

use std::process;

fn main() {
    let result = ntpd::daemon_main();
    process::exit(if result.is_ok() { 0 } else { 1 });
}
