#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![forbid(unsafe_code)]

mod ctl;
mod daemon;
mod force_sync;
mod metrics;

pub use ctl::main as ctl_main;
pub use daemon::main as daemon_main;
pub use metrics::exporter::main as metrics_exporter_main;
