use clap::{AppSettings, Parser};
use fern::colors::Color;
use statime::datastructures::common::{PortIdentity, TimeSource};
use statime::datastructures::datasets::{DefaultDS, DelayMechanism, PortDS, TimePropertiesDS};
use statime::port::Port;
use statime::{
    datastructures::common::ClockIdentity, filters::basic::BasicFilter, ptp_instance::PtpInstance,
};
use statime_linux::{
    clock::{LinuxClock, LinuxTimer, RawLinuxClock},
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
    let colors = fern::colors::ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        .info(Color::BrightGreen)
        .debug(Color::BrightBlue)
        .trace(Color::BrightBlack);

    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%H:%M:%S.%f]"),
                record.target(),
                colors.color(record.level()),
                message
            ))
        })
        .level(level)
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    setup_logger(args.loglevel).expect("Could not setup logging");

    println!("Starting PTP");

    let local_clock = if let Some(hardware_clock) = &args.hardware_clock {
        LinuxClock::new(
            RawLinuxClock::get_from_file(hardware_clock).expect("Could not open hardware clock"),
        )
    } else {
        LinuxClock::new(RawLinuxClock::get_realtime_clock())
    };
    let mut network_runtime = LinuxRuntime::new(args.hardware_clock.is_some(), &local_clock);
    let clock_identity = ClockIdentity(get_clock_id().expect("Could not get clock identity"));

    let default_ds = DefaultDS::new_ordinary_clock(
        clock_identity,
        args.priority_1,
        args.priority_2,
        args.domain,
        false,
        args.sdo,
    );
    let time_properties_ds =
        TimePropertiesDS::new_arbitrary_time(false, false, TimeSource::InternalOscillator);
    let port_ds = PortDS::new(
        PortIdentity {
            clock_identity,
            port_number: 1,
        },
        1,
        args.log_announce_interval,
        args.announce_receipt_timeout,
        args.log_sync_interval,
        DelayMechanism::E2E,
        1,
    );
    let port = Port::new(port_ds, &mut network_runtime, args.interface).await;
    let mut instance = PtpInstance::new_ordinary_clock(
        default_ds,
        time_properties_ds,
        port,
        local_clock,
        BasicFilter::new(0.25),
    );

    instance.run(&LinuxTimer).await;
}
