#![forbid(unsafe_code)]
#![allow(missing_docs)]
// FIXME: the lints below should be reenabled. Please fix them with a per-lint
// PR fixing that one lint and enabling it accross all crates.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ntpd::metrics_exporter_main()
}
