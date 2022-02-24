use std::sync::mpsc;

use statime::{
    datastructures::{common::ClockIdentity, messages::Message},
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
    let clock_id = ClockIdentity(get_clock_id().expect("Could not get clock identity"));

    let config = Config {
        identity: clock_id,
        sdo: 0,
        domain: 0,
        interface: "0.0.0.0".parse().unwrap(),
    };

    let mut instance = PtpInstance::new(config, network_runtime);

    loop {
        let packet = rx.recv().expect("Could not get further network packets");
        // TODO: Implement better mechanism for send timestamps
        let parsed_message = Message::deserialize(&packet.data).unwrap();
        if parsed_message
            .header()
            .source_port_identity()
            .clock_identity
            == clock_id
        {
            if let Some(timestamp) = packet.timestamp {
                instance.handle_send_timestamp(
                    parsed_message.header().sequence_id() as usize,
                    timestamp,
                );
            }
        } else {
            instance.handle_network(packet);
        }
    }
}
