#![forbid(unsafe_code)]

mod security;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    use crate::security::{seccomp_init, drop_caps};

    drop_caps(None);
    seccomp_init(vec!["accept4"]);

    ntpd::metrics_exporter_main()
}
