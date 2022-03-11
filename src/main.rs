use std::{sync::mpsc, time::Duration};

use fixed::traits::LossyFrom;
use statime::{
    clock::linux_clock::{LinuxClock, RawLinuxClock},
    datastructures::{common::ClockIdentity, messages::Message},
    filters::basic::BasicFilter,
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
    let (clock, mut clock_runtime) = LinuxClock::new(RawLinuxClock::get_realtime_clock());
    let clock_id = ClockIdentity(get_clock_id().expect("Could not get clock identity"));

    let config = Config {
        identity: clock_id,
        sdo: 0,
        domain: 0,
        interface: "0.0.0.0".parse().unwrap(),
        port_config: statime::port::PortConfig {
            log_announce_interval: 1,
            priority_1: 255,
            priority_2: 255,
        },
    };

    let mut instance = PtpInstance::new(config, network_runtime, clock, BasicFilter::new(0.25));

    loop {
        let packet = if let Some(timeout) = clock_runtime.interval_to_next_alarm() {
            match rx.recv_timeout(Duration::from_nanos(i128::lossy_from(timeout) as u64)) {
                Ok(data) => Some(data),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(e) => Err(e).expect("Could not get further network packets"),
            }
        } else {
            Some(rx.recv().expect("Could not get further network packets"))
        };
        if let Some(packet) = packet {
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

        while let Some(timer_id) = clock_runtime.check() {
            instance.handle_alarm(timer_id);
        }
    }
}
