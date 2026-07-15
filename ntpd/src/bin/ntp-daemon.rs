#![forbid(unsafe_code)]
#![allow(missing_docs)]
// FIXME: the lints below should be reenabled. Please fix them with a per-lint
// PR fixing that one lint and enabling it accross all crates.
#![allow(clippy::bool_to_int_with_if)]

use std::process;

fn main() {
    let result = ntpd::daemon_main();
    process::exit(if result.is_ok() { 0 } else { 1 });
}
