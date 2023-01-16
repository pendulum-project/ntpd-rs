use std::sync::mpsc;

use clap::{AppSettings, Parser};

use statime::{
    datastructures::{common::ClockIdentity, messages::Message},
    filters::basic::BasicFilter,
    ptp_instance::{Config, PtpInstance},
};
use statime_linux::{
    clock::{LinuxClock, RawLinuxClock},
    network::linux::{get_clock_id, LinuxInterfaceDescriptor, LinuxRuntime},
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None, setting = AppSettings::DeriveDisplayOrder)]
struct Args {
    /// Set desired logging level
    #[clap(short, long, default_value_t = log::LevelFilter::Info)]
    loglevel: log::LevelFilter,

    /// Set interface on which to listen to PTP messages
    #[clap(short, long)]
    interface: LinuxInterfaceDescriptor,

    /// The SDO id of the desired ptp domain
    #[clap(long, default_value_t = 0)]
    sdo: u16,

    /// The domain number of the desired ptp domain
    #[clap(long, default_value_t = 0)]
    domain: u8,

    /// Local clock priority (part 1) used in master clock selection
    #[clap(long, default_value_t = 128)]
    priority_1: u8,

    /// Locqal clock priority (part 2) used in master clock selection
    #[clap(long, default_value_t = 128)]
    priority_2: u8,

    /// Log value of interval expected between announce messages
    #[clap(long, default_value_t = 1)]
    log_announce_interval: i8,

    /// The timeout interval to wait for announce messages before
    /// swithing to the master state
    #[clap(long, default_value_t = 5)]
    announce_receipt_timeout_interval: i32,

    #[clap(long, default_value_t = 1)]
    announce_interval: i32,

    #[clap(long, default_value_t = 1)]
    sync_interval: i32,

    /// Use hardware clock
    #[clap(long, short)]
    hardware_clock: Option<String>,
}

fn setup_logger(level: log::LevelFilter) -> Result<(), fern::InitError> {
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
        .level(level)
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}

fn main() {
    let args = Args::parse();

    setup_logger(args.loglevel).expect("Could not setup logging");
    let (tx, rx) = mpsc::channel();
    let network_runtime = LinuxRuntime::new(tx, args.hardware_clock.is_some());
    let (clock, mut clock_runtime) = if let Some(hardware_clock) = &args.hardware_clock {
        LinuxClock::new(
            RawLinuxClock::get_from_file(hardware_clock).expect("Could not open hardware clock"),
        )
    } else {
        LinuxClock::new(RawLinuxClock::get_realtime_clock())
    };
    let clock_id = ClockIdentity(get_clock_id().expect("Could not get clock identity"));

    let config = Config {
        identity: clock_id,
        sdo: args.sdo,
        domain: args.domain,
        interface: args.interface,
        port_config: statime::port::PortConfig {
            log_announce_interval: args.log_announce_interval,
            announce_receipt_timeout_interval: args.announce_receipt_timeout_interval,
            priority_1: args.priority_1,
            priority_2: args.priority_2,
            announce_interval: args.announce_interval,
            sync_interval: args.sync_interval,
        },
    };

    let mut instance = PtpInstance::new(config, network_runtime, clock, BasicFilter::new(0.25));

    loop {
        let packet = if let Some(timeout) = clock_runtime.interval_to_next_alarm() {
            match rx.recv_timeout(std::time::Duration::from_nanos(timeout.nanos().to_num())) {
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
