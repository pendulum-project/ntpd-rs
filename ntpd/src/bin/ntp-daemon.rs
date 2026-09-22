#![forbid(unsafe_code)]
#![allow(missing_docs)]
// FIXME: the lints below should be reenabled. Please fix them with a per-lint
// PR fixing that one lint and enabling it accross all crates.
#![allow(clippy::bool_to_int_with_if)]

use std::process;

fn main() {
    if let Err(err) = ntpd::daemon_main() {
        eprintln!("{err}");
        process::exit(1);
    } else {
        process::exit(0);
    }
}
