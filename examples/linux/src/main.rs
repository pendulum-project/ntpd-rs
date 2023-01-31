use std::sync::mpsc;

use clap::{AppSettings, Parser};

use statime::datastructures::common::{PortIdentity, TimeSource};
use statime::datastructures::datasets::{DefaultDS, DelayMechanism, PortDS, TimePropertiesDS};
use statime::{
    datastructures::{common::ClockIdentity, messages::Message},
    filters::basic::BasicFilter,
    ptp_instance::PtpInstance,
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
    /// Default init value is 128, see: A.9.4.2
    #[clap(long, default_value_t = 255)]
    priority_1: u8,

    /// Local clock priority (part 2) used in master clock selection
    /// Default init value is 128, see: A.9.4.2
    #[clap(long, default_value_t = 255)]
    priority_2: u8,

    /// Log value of interval expected between announce messages, see: 7.7.2.2
    /// Default init value is 1, see: A.9.4.2
    #[clap(long, default_value_t = 1)]
    log_announce_interval: i8,

    /// Time interval between Sync messages, see: 7.7.2.3
    /// Default init value is 0, see: A.9.4.2
    #[clap(long, default_value_t = 0)]
    log_sync_interval: i8,

    /// Default init value is 3, see: A.9.4.2
    #[clap(long, default_value_t = 3)]
    announce_receipt_timeout: u8,

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
    let clock_identity = ClockIdentity(get_clock_id().expect("Could not get clock identity"));

    let default_ds = DefaultDS::new_oc(clock_identity, 128, 128, args.domain, false, args.sdo);
    let time_properties_ds =
        TimePropertiesDS::new_arbitrary(false, false, TimeSource::InternalOscillator);
    let port_ds = PortDS::new(
        PortIdentity {
            clock_identity,
            port_number: 1,
        },
        37,
        args.log_announce_interval,
        args.announce_receipt_timeout,
        args.log_sync_interval,
        DelayMechanism::E2E,
        37,
        0,
        1,
    );

    let mut instance = PtpInstance::new(
        default_ds,
        time_properties_ds,
        port_ds,
        args.interface,
        network_runtime,
        clock,
        BasicFilter::new(0.25),
    );

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
                == clock_identity
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
