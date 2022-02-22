use std::sync::mpsc;

use statime::{
    datastructures::common::ClockIdentity,
    network::linux::{get_clock_id, LinuxRuntime},
    ptp_instance::{Config, PtpInstance},
};

fn setup_logger() -> Result<(), fern::InitError> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::Debug)
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}

fn main() {
    setup_logger().expect("Could not setup logging");
    let (tx, rx) = mpsc::channel();
    let network_runtime = LinuxRuntime::new(tx);

    let config = Config {
        identity: ClockIdentity(get_clock_id().expect("Could not get clock identity")),
        sdo: 0,
        domain: 0,
        interface: "0.0.0.0".parse().unwrap(),
    };

    let mut instance = PtpInstance::new(config, network_runtime);

    loop {
        let packet = rx.recv().expect("Could not get further network packets");
        instance.handle_network(packet);
    }
}
