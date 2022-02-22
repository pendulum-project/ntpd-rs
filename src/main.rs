use std::sync::mpsc;

use statime::{
    datastructures::common::ClockIdentity,
    network::linux::{get_clock_id, LinuxRuntime},
    port::Port,
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
    let identity = ClockIdentity(get_clock_id().expect("Could not get clock identity"));

    let mut port = Port::new(
        identity,
        0,
        0,
        0,
        network_runtime,
        "0.0.0.0".parse().unwrap(),
    );

    loop {
        let packet = rx.recv().expect("Could not get further network packets");
        port.handle_network(packet);
        if let Some(data) = port.extract_measurement() {
            println!("Offset to master: {}", data);
        }
    }
}
