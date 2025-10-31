#![forbid(unsafe_code)]

mod ctl;
mod daemon;
mod force_sync;
mod metrics;
mod security;
    
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
