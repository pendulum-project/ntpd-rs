use std::{
    future::Future,
    path::PathBuf,
    pin::{pin, Pin},
    str::FromStr,
};

use clap::Parser;
use fern::colors::Color;
use rand::{rngs::StdRng, SeedableRng};
use statime::{
    BasicFilter, Clock, ClockIdentity, InBmca, InstanceConfig, Port, PortAction,
    PortActionIterator, PtpInstance, SdoId, Time, TimePropertiesDS, TimeSource, TimestampContext,
    MAX_DATA_LEN,
};
use statime_linux::{
    clock::LinuxClock,
    config::Config,
    socket::{EventSocket, GeneralSocket},
};
use timestamped_socket::{
    interface::{InterfaceDescriptor, InterfaceIterator},
    raw_udp_socket::TimestampingMode,
};
use tokio::{
    sync::mpsc::{Receiver, Sender},
    time::Sleep,
};

#[derive(Clone, Copy)]
struct SdoIdParser;

pub struct PortDefinition {
    port: BmcaPort,
    interface: InterfaceDescriptor,
    timestamping_mode: TimestampingMode,
}

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
pub struct Args {
    /// Time interval between Sync messages, see: 7.7.2.3
    /// Default init value is 0, see: A.9.4.2
    #[clap(long, short = 'c', default_value = "config.toml")]
    config_file: Option<PathBuf>,
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

    let config = Config::from_file(
        &args
            .config_file
            .expect("could not determine config file path"),
    )
    .unwrap_or_else(|e| panic!("error loading config: {e}"));

    let log_level = log::LevelFilter::from_str(&config.loglevel).unwrap();
    setup_logger(log_level).expect("could not setup logging");

    let local_clock = if let Some(hardware_clock) = config.hardware_clock {
        LinuxClock::open(hardware_clock).expect("could not open hardware clock")
    } else {
        LinuxClock::CLOCK_REALTIME
    };

    let clock_identity = ClockIdentity(get_clock_id().expect("could not get clock identity"));

    let instance_config = InstanceConfig {
        clock_identity,
        priority_1: config.priority1,
        priority_2: config.priority2,
        domain_number: config.domain,
        slave_only: false,
        sdo_id: SdoId::new(config.sdo_id).expect("sdo-id should be between 0 and 4095"),
    };

    let time_properties_ds =
        TimePropertiesDS::new_arbitrary_time(false, false, TimeSource::InternalOscillator);

    // Leak to get a static reference, the ptp instance will be around for the rest
    // of the program anyway
    let instance = Box::leak(Box::new(PtpInstance::new(
        instance_config,
        time_properties_ds,
    )));

    // for every port in the config file, create a port definition and add it
    // to the instance
    let ports = config.ports.into_iter().map(|port_config| {
        let interface = InterfaceDescriptor::from_str(port_config.interface.as_str()).unwrap();
        // NOTE: Hardware timestamping is ignored for now
        // let timestamping_mode = if config.hardware_clock.is_some() {
        // match interface_descriptor.interface_name {
        // Some(interface_name) => TimestampingMode::Hardware(interface_name),
        // None => panic!("an interface name is required when using hardware
        // timestamping"), }
        // } else {
        // TimestampingMode::Software
        // };
        let timestamping_mode = TimestampingMode::Software;
        let rng = StdRng::from_entropy();
        let port = instance.add_port(port_config.into(), 0.25, local_clock.clone(), rng);

        PortDefinition {
            port,
            interface,
            timestamping_mode,
        }
    });

    run(ports, &local_clock, instance).await.unwrap()
}

async fn run(
    ports: impl Iterator<Item = PortDefinition> + ExactSizeIterator,
    local_clock: &LinuxClock,
    instance: &'static PtpInstance<BasicFilter>,
) -> std::io::Result<()> {
    let (bmca_notify_sender, bmca_notify_receiver) = tokio::sync::watch::channel(false);

    let mut main_task_senders = Vec::with_capacity(ports.len());
    let mut main_task_receivers = Vec::with_capacity(ports.len());

    for port_definition in ports.into_iter() {
        let event_socket = EventSocket::new(
            &port_definition.interface,
            port_definition.timestamping_mode,
        )
        .await?;
        let general_socket = GeneralSocket::new(&port_definition.interface).await?;

        let (main_task_sender, port_task_receiver) = tokio::sync::mpsc::channel(1);
        let (port_task_sender, main_task_receiver) = tokio::sync::mpsc::channel(1);

        tokio::spawn(port_task(
            port_task_receiver,
            port_task_sender,
            event_socket,
            general_socket,
            local_clock.clone(),
            bmca_notify_receiver.clone(),
        ));

        main_task_sender
            .send(port_definition.port)
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
        bmca_notify_sender
            .send(true)
            .expect("Bmca notification failed");

        let mut bmca_ports = Vec::with_capacity(main_task_receivers.len());
        let mut mut_bmca_ports = Vec::with_capacity(main_task_receivers.len());

        for receiver in main_task_receivers.iter_mut() {
            bmca_ports.push(receiver.recv().await.unwrap());
        }

        // have all ports so deassert stop
        bmca_notify_sender
            .send(false)
            .expect("Bmca notification failed");

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
    mut bmca_notify: tokio::sync::watch::Receiver<bool>,
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
                result = bmca_notify.wait_for(|v| *v) => match result {
                    Ok(_) => break,
                    Err(error) => panic!("Error on bmca notify: {error:?}"),
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
