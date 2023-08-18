use std::{
    future::Future,
    pin::{pin, Pin},
    sync::OnceLock,
};

use clap::Parser;
use fern::colors::Color;
use rand::{rngs::StdRng, SeedableRng};
use statime::{
    BasicFilter, Clock, ClockIdentity, DelayMechanism, Duration, InBmca, InstanceConfig, Interval,
    Port, PortAction, PortActionIterator, PortConfig, PtpInstance, SdoId, Time, TimePropertiesDS,
    TimeSource, TimestampContext, MAX_DATA_LEN,
};
use statime_linux::{
    clock::LinuxClock,
    socket::{EventSocket, GeneralSocket},
};
use timestamped_socket::{
    interface::{InterfaceDescriptor, InterfaceIterator},
    raw_udp_socket::TimestampingMode,
};
use tokio::{
    sync::{
        mpsc::{Receiver, Sender},
        Notify,
    },
    time::Sleep,
};

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

pin_project_lite::pin_project! {
    struct Timer {
        #[pin]
        timer: Sleep,
        running: bool,
    }
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

    let local_clock = if let Some(hardware_clock) = &args.hardware_clock {
        LinuxClock::open(hardware_clock).expect("Could not open hardware clock")
    } else {
        LinuxClock::CLOCK_REALTIME
    };

    let timestamping_mode = if args.hardware_clock.is_some() {
        match args.interface.interface_name {
            Some(interface_name) => TimestampingMode::Hardware(interface_name),
            None => panic!("an interface name is required when using hardware timestamping"),
        }
    } else {
        TimestampingMode::Software
    };

    let clock_identity = ClockIdentity(get_clock_id().expect("Could not get clock identity"));

    let config = InstanceConfig {
        clock_identity,
        priority_1: args.priority_1,
        priority_2: args.priority_2,
        domain_number: args.domain,
        slave_only: false,
        sdo_id: args.sdo,
    };

    let time_properties_ds =
        TimePropertiesDS::new_arbitrary_time(false, false, TimeSource::InternalOscillator);

    let instance = PtpInstance::new(config, time_properties_ds, local_clock.clone());

    // borrow instance with the static lifetime
    static INSTANCE: OnceLock<PtpInstance<LinuxClock, BasicFilter>> = OnceLock::new();
    let instance = INSTANCE.get_or_init(|| instance);

    let port_config = PortConfig {
        delay_mechanism: DelayMechanism::E2E {
            interval: Interval::TWO_SECONDS,
        },
        announce_interval: Interval::from_log_2(args.log_announce_interval),
        announce_receipt_timeout: args.announce_receipt_timeout,
        sync_interval: Interval::from_log_2(args.log_sync_interval),
        master_only: false,
        delay_asymmetry: Duration::ZERO,
    };

    let rng1 = StdRng::from_entropy();
    let port_in_bmca1 = instance.add_port(port_config, 0.25, local_clock.clone(), rng1);

    let rng2 = StdRng::from_entropy();
    let port_in_bmca2 = instance.add_port(port_config, 0.25, local_clock.clone(), rng2);

    let ports = vec![port_in_bmca1, port_in_bmca2];

    run(
        ports,
        &args.interface,
        timestamping_mode,
        &local_clock,
        instance,
    )
    .await
    .unwrap()
}

async fn run(
    ports: Vec<BmcaPort>,
    interface: &InterfaceDescriptor,
    timestamping_mode: TimestampingMode,
    local_clock: &LinuxClock,
    instance: &'static PtpInstance<LinuxClock, BasicFilter>,
) -> std::io::Result<()> {
    static BMCA_NOTIFY: OnceLock<Notify> = OnceLock::new();
    let bmca_notify = BMCA_NOTIFY.get_or_init(Notify::new);

    let mut main_task_senders = Vec::with_capacity(ports.len());
    let mut main_task_receivers = Vec::with_capacity(ports.len());

    for port in ports.into_iter() {
        let event_socket = EventSocket::new(interface, timestamping_mode).await?;
        let general_socket = GeneralSocket::new(interface).await?;

        let (main_task_sender, port_task_receiver) = tokio::sync::mpsc::channel(1);
        let (port_task_sender, main_task_receiver) = tokio::sync::mpsc::channel(1);

        tokio::spawn(port_task(
            port_task_receiver,
            port_task_sender,
            event_socket,
            general_socket,
            local_clock.clone(),
            bmca_notify,
        ));

        main_task_sender
            .send(port)
            .await
            .expect("space in channel buffer");

        main_task_senders.push(main_task_sender);
        main_task_receivers.push(main_task_receiver);
    }

    // run bmca over all of the ports at the same time. The ports don't perform
    // their normal actions at this time: bmca is stop-the-world!
    let mut bmca_timer = pin!(Timer::new());

    loop {
        // reset bmca timer
        bmca_timer.as_mut().reset(instance.bmca_interval());

        // wait until the next BMCA
        bmca_timer.as_mut().await;

        // notify all the ports that they need to stop what they're doing
        bmca_notify.notify_waiters();

        let mut bmca_ports = Vec::with_capacity(main_task_receivers.len());
        let mut mut_bmca_ports = Vec::with_capacity(main_task_receivers.len());

        for receiver in main_task_receivers.iter_mut() {
            bmca_ports.push(receiver.recv().await.unwrap());
        }

        for mut_bmca_port in bmca_ports.iter_mut() {
            mut_bmca_ports.push(mut_bmca_port);
        }

        instance.bmca(&mut mut_bmca_ports);

        drop(mut_bmca_ports);

        for (port, sender) in bmca_ports.into_iter().zip(main_task_senders.iter()) {
            sender.send(port).await.unwrap();
        }
    }
}

type BmcaPort = Port<InBmca<'static>, StdRng, LinuxClock, BasicFilter>;

// the Port task
//
// This task waits for a new port (in the bmca state) to arrive on its Receiver.
// It will then move the port into the running state, and process actions. When
// the task is notified of a BMCA, it will stop running, move the port into the
// bmca state, and send it on its Sender
async fn port_task(
    mut port_task_receiver: Receiver<BmcaPort>,
    port_task_sender: Sender<BmcaPort>,
    mut event_socket: EventSocket,
    mut general_socket: GeneralSocket,
    local_clock: LinuxClock,
    bmca_notify: &Notify,
) {
    let mut timers = Timers {
        port_sync_timer: pin!(Timer::new()),
        port_announce_timer: pin!(Timer::new()),
        port_announce_timeout_timer: pin!(Timer::new()),
        delay_request_timer: pin!(Timer::new()),
        filter_update_timer: pin!(Timer::new()),
    };

    loop {
        let port_in_bmca = port_task_receiver.recv().await.unwrap();

        // handle post-bmca actions
        let (mut port, actions) = port_in_bmca.end_bmca();

        let mut pending_timestamp = handle_actions(
            actions,
            &mut event_socket,
            &mut general_socket,
            &mut timers,
            &local_clock,
        )
        .await;

        while let Some((context, timestamp)) = pending_timestamp {
            pending_timestamp = handle_actions(
                port.handle_send_timestamp(context, timestamp),
                &mut event_socket,
                &mut general_socket,
                &mut timers,
                &local_clock,
            )
            .await;
        }

        let mut event_buffer = [0; MAX_DATA_LEN];
        let mut general_buffer = [0; 2048];

        loop {
            let mut actions = tokio::select! {
                result = event_socket.recv(&local_clock, &mut event_buffer) => match result {
                    Ok(packet) => port.handle_timecritical_receive(packet.data, packet.timestamp),
                    Err(error) => panic!("Error receiving: {error:?}"),
                },
                result = general_socket.recv(&mut general_buffer) => match result {
                    Ok(packet) => port.handle_general_receive(packet.data),
                    Err(error) => panic!("Error receiving: {error:?}"),
                },
                () = &mut timers.port_announce_timer => {
                    port.handle_announce_timer()
                },
                () = &mut timers.port_sync_timer => {
                    port.handle_sync_timer()
                },
                () = &mut timers.port_announce_timeout_timer => {
                    port.handle_announce_receipt_timer()
                },
                () = &mut timers.delay_request_timer => {
                    port.handle_delay_request_timer()
                },
                () = &mut timers.filter_update_timer => {
                    port.handle_filter_update_timer()
                },
                () = bmca_notify.notified() => {
                    break;
                }
            };

            loop {
                let pending_timestamp = handle_actions(
                    actions,
                    &mut event_socket,
                    &mut general_socket,
                    &mut timers,
                    &local_clock,
                )
                .await;

                // there might be more actions to handle based on the current action
                actions = match pending_timestamp {
                    Some((context, timestamp)) => port.handle_send_timestamp(context, timestamp),
                    None => break,
                };
            }
        }

        let port_in_bmca = port.start_bmca();
        port_task_sender.send(port_in_bmca).await.unwrap();
    }
}

struct Timers<'a> {
    port_sync_timer: Pin<&'a mut Timer>,
    port_announce_timer: Pin<&'a mut Timer>,
    port_announce_timeout_timer: Pin<&'a mut Timer>,
    delay_request_timer: Pin<&'a mut Timer>,
    filter_update_timer: Pin<&'a mut Timer>,
}

async fn handle_actions(
    actions: PortActionIterator<'_>,
    event_socket: &mut EventSocket,
    general_socket: &mut GeneralSocket,
    timers: &mut Timers<'_>,
    local_clock: &LinuxClock,
) -> Option<(TimestampContext, Time)> {
    let mut pending_timestamp = None;

    for action in actions {
        match action {
            PortAction::SendTimeCritical { context, data } => {
                // send timestamp of the send
                let time = event_socket
                    .send(data)
                    .await
                    .unwrap()
                    .unwrap_or(local_clock.now());

                // anything we send later will have a later pending (send) timestamp
                pending_timestamp = Some((context, time));
            }
            PortAction::SendGeneral { data } => {
                general_socket.send(data).await.unwrap();
            }
            PortAction::ResetAnnounceTimer { duration } => {
                timers.port_announce_timer.as_mut().reset(duration);
            }
            PortAction::ResetSyncTimer { duration } => {
                timers.port_sync_timer.as_mut().reset(duration);
            }
            PortAction::ResetDelayRequestTimer { duration } => {
                timers.delay_request_timer.as_mut().reset(duration);
            }
            PortAction::ResetAnnounceReceiptTimer { duration } => {
                timers.port_announce_timeout_timer.as_mut().reset(duration);
            }
            PortAction::ResetFilterUpdateTimer { duration } => {
                timers.filter_update_timer.as_mut().reset(duration);
            }
        }
    }

    pending_timestamp
}

fn get_clock_id() -> Option<[u8; 8]> {
    let candidates = InterfaceIterator::new()
        .unwrap()
        .filter_map(|data| data.mac);

    for mac in candidates {
        // Ignore multicast and locally administered mac addresses
        if mac[0] & 0x3 == 0 && mac.iter().any(|x| *x != 0) {
            let f = |i| mac.get(i).copied().unwrap_or_default();
            return Some(std::array::from_fn(f));
        }
    }

    None
}
