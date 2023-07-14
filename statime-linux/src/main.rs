use std::{future::Future, pin::Pin};

use clap::Parser;
use fern::colors::Color;
use statime::{
    BasicFilter, ClockIdentity, DefaultDS, DelayMechanism, Duration, Interval, PortActionIterator,
    PortConfig, PortIdentity, PtpInstance, SdoId, Time, TimePropertiesDS, TimeSource,
    TimestampContext,
};
use statime_linux::{
    clock::{LinuxClock, RawLinuxClock},
    network::linux::{get_clock_id, InterfaceDescriptor, LinuxRuntime, TimestampingMode},
};
use tokio::{pin, time::Sleep};

#[derive(Clone, Copy)]
struct SdoIdParser;

impl clap::builder::TypedValueParser for SdoIdParser {
    type Value = SdoId;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        use clap::error::{ContextKind, ContextValue, ErrorKind};

        let inner = clap::value_parser!(u16);
        let val = inner.parse_ref(cmd, arg, value)?;

        match SdoId::new(val) {
            None => {
                let mut err = clap::Error::new(ErrorKind::ValueValidation).with_cmd(cmd);
                if let Some(arg) = arg {
                    err.insert(
                        ContextKind::InvalidArg,
                        ContextValue::String(arg.to_string()),
                    );
                }
                err.insert(
                    ContextKind::InvalidValue,
                    ContextValue::String(val.to_string()),
                );
                Err(err)
            }
            Some(v) => Ok(v),
        }
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Set desired logging level
    #[clap(short, long, default_value_t = log::LevelFilter::Info)]
    loglevel: log::LevelFilter,

    /// Set interface on which to listen to PTP messages
    #[clap(short, long)]
    interface: InterfaceDescriptor,

    /// The SDO id of the desired ptp domain
    #[clap(long, default_value_t = SdoId::default(), value_parser = SdoIdParser)]
    sdo: SdoId,

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
    #[clap(long, short = 'c')]
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
            use std::time::{SystemTime, UNIX_EPOCH};

            let delta = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

            let h = delta.as_secs() % (24 * 60 * 60) / (60 * 60);
            let m = delta.as_secs() % (60 * 60) / 60;
            let s = delta.as_secs() % 60;
            let f = delta.as_secs_f64().fract() * 1e7;

            out.finish(format_args!(
                "{}[{}][{}] {}",
                format_args!("[{h:02}:{m:02}:{s:02}.{f:07}]"),
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

#[pin_project::pin_project]
struct Timer {
    #[pin]
    timer: Sleep,
    running: bool,
}

impl Timer {
    fn new() -> Self {
        Timer {
            timer: tokio::time::sleep(std::time::Duration::from_secs(0)),
            running: false,
        }
    }

    fn reset(self: Pin<&mut Self>, duration: std::time::Duration) {
        let this = self.project();
        this.timer.reset(tokio::time::Instant::now() + duration);
        *this.running = true;
    }
}

impl Future for Timer {
    type Output = ();

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        if *this.running {
            let result = this.timer.poll(cx);
            if result != std::task::Poll::Pending {
                *this.running = false;
            }
            result
        } else {
            std::task::Poll::Pending
        }
    }
}

#[tokio::main]
async fn main() {
    actual_main().await;
}

async fn actual_main() {
    let args = Args::parse();

    setup_logger(args.loglevel).expect("Could not setup logging");

    println!("Starting PTP");

    let local_clock = if let Some(hardware_clock) = &args.hardware_clock {
        let clock =
            RawLinuxClock::get_from_file(hardware_clock).expect("Could not open hardware clock");
        LinuxClock::new(clock)
    } else {
        LinuxClock::new(RawLinuxClock::get_realtime_clock())
    };

    let timestamping_mode = if args.hardware_clock.is_some() {
        match args.interface.interface_name {
            Some(interface_name) => TimestampingMode::Hardware(interface_name),
            None => panic!("an interface name is required when using hardware timestamping"),
        }
    } else {
        TimestampingMode::Software
    };

    let mut network_runtime = LinuxRuntime::new(timestamping_mode, local_clock.clone());
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
    let port_config = PortConfig {
        port_identity: PortIdentity {
            clock_identity,
            port_number: 1,
        },
        delay_mechanism: DelayMechanism::E2E {
            interval: Interval::TWO_SECONDS,
        },
        announce_interval: Interval::from_log_2(args.log_announce_interval),
        announce_receipt_timeout: args.announce_receipt_timeout,
        sync_interval: Interval::from_log_2(args.log_sync_interval),
        master_only: false,
        delay_asymmetry: Duration::ZERO,
    };

    let instance = PtpInstance::new(
        default_ds,
        time_properties_ds,
        local_clock,
        BasicFilter::new(0.25),
    );
    let mut bmca_port = instance.add_port(port_config);

    let bmca_timer = Timer::new();
    let port_sync_timer = Timer::new();
    let port_announce_timer = Timer::new();
    let port_announce_timeout_timer = Timer::new();

    pin!(bmca_timer);
    pin!(port_sync_timer);
    pin!(port_announce_timer);
    pin!(port_announce_timeout_timer);

    let mut network_port = network_runtime.open(args.interface).await.unwrap();

    loop {
        // reset bmca timer
        bmca_timer.as_mut().reset(instance.bmca_interval());

        // handle post-bmca actions
        let (mut port, actions) = bmca_port.end_bmca();
        let mut pending_timestamp = handle_actions(
            actions,
            &mut network_port,
            &mut port_announce_timer,
            &mut port_sync_timer,
            &mut port_announce_timeout_timer,
        )
        .await;
        while let Some((context, timestamp)) = pending_timestamp.take() {
            let actions = port.handle_send_timestamp(context, timestamp);
            pending_timestamp = handle_actions(
                actions,
                &mut network_port,
                &mut port_announce_timer,
                &mut port_sync_timer,
                &mut port_announce_timeout_timer,
            )
            .await;
        }

        loop {
            println!("Inner loop");
            let actions = tokio::select! {
                result = network_port.recv() => {
                    match result {
                        Ok(packet) => {
                            match packet.timestamp {
                                Some(timestamp) => port.handle_timecritical_receive(&packet.data, timestamp),
                                None => port.handle_general_receive(&packet.data),
                            }
                        },
                        Err(error) => panic!("Error receiving: {:?}", error),
                    }
                },
                () = &mut port_announce_timer => {
                    port.handle_announce_timer()
                },
                () = &mut port_sync_timer => {
                    port.handle_sync_timer()
                },
                () = &mut port_announce_timeout_timer => {
                    port.handle_announce_receipt_timer()
                },
                () = &mut bmca_timer => {
                    break;
                }
            };

            let mut pending_timestamp = handle_actions(
                actions,
                &mut network_port,
                &mut port_announce_timer,
                &mut port_sync_timer,
                &mut port_announce_timeout_timer,
            )
            .await;
            while let Some((context, timestamp)) = pending_timestamp.take() {
                let actions = port.handle_send_timestamp(context, timestamp);
                pending_timestamp = handle_actions(
                    actions,
                    &mut network_port,
                    &mut port_announce_timer,
                    &mut port_sync_timer,
                    &mut port_announce_timeout_timer,
                )
                .await;
            }
        }

        bmca_port = port.start_bmca();

        instance.bmca(&mut [&mut bmca_port]);
    }
}

async fn handle_actions(
    actions: PortActionIterator<'_>,
    network_port: &mut statime_linux::network::linux::LinuxNetworkPort,
    port_announce_timer: &mut Pin<&mut Timer>,
    port_sync_timer: &mut Pin<&mut Timer>,
    port_announce_timeout_timer: &mut Pin<&mut Timer>,
) -> Option<(TimestampContext, Time)> {
    let mut pending_timestamp = None;
    for action in actions {
        match action {
            statime::PortAction::SendTimeCritical { context, data } => {
                pending_timestamp = Some((
                    context,
                    network_port
                        .send_time_critical(data)
                        .await
                        .unwrap()
                        .unwrap(),
                ))
            }
            statime::PortAction::SendGeneral { data } => network_port.send(data).await.unwrap(),
            statime::PortAction::ResetAnnounceTimer { duration } => {
                port_announce_timer.as_mut().reset(duration)
            }
            statime::PortAction::ResetSyncTimer { duration } => {
                port_sync_timer.as_mut().reset(duration)
            }
            statime::PortAction::ResetAnnounceReceiptTimer { duration } => {
                port_announce_timeout_timer.as_mut().reset(duration)
            }
        }
    }
    pending_timestamp
}
