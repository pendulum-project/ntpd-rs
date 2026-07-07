#![forbid(unsafe_code)]
#![allow(missing_docs)]
// FIXME: the lints below should be reenabled. Please fix them with a per-lint
// PR fixing that one lint and enabling it accross all crates.
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::enum_glob_use)]
#![allow(clippy::float_cmp)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::unreadable_literal)]

mod ctl;
mod daemon;
mod force_sync;
mod metrics;
mod notify;

pub use ctl::main as ctl_main;
pub use daemon::main as daemon_main;
pub use metrics::exporter::main as metrics_exporter_main;

#[cfg(test)]
mod test {
    use std::sync::atomic::{AtomicU16, Ordering};

    pub fn alloc_port() -> u16 {
        static PORT: AtomicU16 = AtomicU16::new(5000);
        PORT.fetch_add(1, Ordering::Relaxed)
    }
}
