#![forbid(unsafe_code)]

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ntpd::metrics_exporter_main()
}
