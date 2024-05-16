use std::{future::Future, marker::PhantomData, net::SocketAddr, pin::Pin};
use std::marker::PhantomData;
use std::pin::Pin;
use tokio::io::AsyncReadExt;
use tokio_serial::SerialStream;
use tokio::time::{Instant, Sleep};

use ntp_proto::{
    NtpClock, NtpInstant, NtpSource, NtpSourceActionIterator, NtpSourceUpdate, NtpTimestamp,
    ProtocolVersion, SourceDefaultsConfig, SourceNtsData, SystemSnapshot, GpsSourceActionIterator, GpsSource
};
#[cfg(target_os = "linux")]
use timestamped_socket::socket::open_interface_udp;
use timestamped_socket::{
    interface::InterfaceName,
    socket::{connect_address, Connected, RecvResult, Socket},
};
use tracing::{debug, error, info_span, instrument, warn, Instrument, Span, info};


use super::{config::TimestampMode, exitcode, spawn::SourceId, util::convert_net_timestamp};

/// Trait needed to allow injecting of futures other than `tokio::time::Sleep` for testing
pub trait Wait: Future<Output = ()> {
    fn reset(self: Pin<&mut Self>, deadline: Instant);
}

impl Wait for Sleep {
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        self.reset(deadline);
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum MsgForSystem {
    /// Received a Kiss-o'-Death and must demobilize
    MustDemobilize(SourceId),
    /// Experienced a network issue and must be restarted
    NetworkIssue(SourceId),
    /// Source is unreachable, and should be restarted with new resolved addr.
    Unreachable(SourceId),
    /// Update from source
    SourceUpdate(SourceId, NtpSourceUpdate),
}

#[derive(Debug, Clone)]
pub struct SourceChannels {
    pub msg_for_system_sender: tokio::sync::mpsc::Sender<MsgForSystem>,
    pub system_snapshot_receiver: tokio::sync::watch::Receiver<SystemSnapshot>,
}

pub(crate) struct GpsSourceTask<C: 'static + NtpClock + Send, T: Wait> {
    _wait: PhantomData<T>,
    index: SourceId,
    clock: C,
    interface: Option<InterfaceName>,
    serial_port: SerialStream,
    timestamp_mode: TimestampMode,
    source_addr: SocketAddr,
    socket: Option<Socket<SocketAddr, Connected>>,
    channels: SourceChannels,

    source: GpsSource,

    // we don't store the real origin timestamp in the packet, because that would leak our
    // system time to the network (and could make attacks easier). So instead there is some
    // garbage data in the origin_timestamp field, and we need to track and pass along the
    // actual origin timestamp ourselves.
    /// Timestamp of the last packet that we sent
    last_send_timestamp: Option<NtpTimestamp>,
    gps: GPS,
}

#[derive(Debug)]
enum SocketResult {
    Ok,
    Abort,
}

impl<C, T> GpsSourceTask<C, T>
where
    C: 'static + NtpClock + Send + Sync,
    T: Wait,
{
    async fn setup_socket(&mut self) -> SocketResult {
        let socket_res = match self.interface {
            #[cfg(target_os = "linux")]
            Some(interface) => {
                open_interface_udp(
                    interface,
                    0, /*lets os choose*/
                    self.timestamp_mode.as_interface_mode(),
                    None,
                )
                .and_then(|socket| socket.connect(self.source_addr))
            }
            _ => connect_address(self.source_addr, self.timestamp_mode.as_general_mode()),
        };

        self.socket = match socket_res {
            Ok(socket) => Some(socket),
            Err(error) => {
                warn!(?error, "Could not open socket");
                return SocketResult::Abort;
            }
        };

        SocketResult::Ok
    }

    async fn run(&mut self, mut poll_wait: Pin<&mut T>) {
        loop {
            enum SelectResult {
                Timer,
                Recv(Result<GPSData, GPSError>),
            }
           
            let selected = tokio::select! {
                () = &mut poll_wait => {
                    SelectResult::Timer
                },
                result = SelectResult::Recv(self.gps.current_data()),
            };

            let actions = match selected {
                SelectResult::Recv(result) => {
                    tracing::debug!("accept gps time stamp");
                    match accept_GPSTime(result, &buf, &self.clock) {
                        AcceptResult::Accept(recv_timestamp) => {
                            let send_timestamp = match self.last_send_timestamp {
                                Some(ts) => ts,
                                None => {
                                    debug!(
                                        "we received a message without having sent one; discarding"
                                    );
                                    continue;
                                }
                            };

                            let system_snapshot = *self.channels.system_snapshot_receiver.borrow();
                            self.source.handle_incoming(
                                system_snapshot,
                                packet,
                                NtpInstant::now(),
                                send_timestamp,
                                recv_timestamp,
                            )
                        }
                       
                        AcceptResult::Ignore => GpsSourceActionIterator::default(),
                    }
                }
                SelectResult::Timer => {
                    tracing::debug!("wait completed");
                    let system_snapshot = *self.channels.system_snapshot_receiver.borrow();
                    self.source.handle_timer(system_snapshot)
                }
            };

            for action in actions {
                match action {
                    ntp_proto::GpsSourceAction::Send(packet) => {
                        if matches!(self.setup_socket().await, SocketResult::Abort) {
                            self.channels
                                .msg_for_system_sender
                                .send(MsgForSystem::NetworkIssue(self.index))
                                .await
                                .ok();
                            return;
                        }

                        match self.clock.now() {
                            Err(e) => {
                                // we cannot determine the origin_timestamp
                                error!(error = ?e, "There was an error retrieving the current time");

                                // report as no permissions, since this seems the most likely
                                std::process::exit(exitcode::NOPERM);
                            }
                            Ok(ts) => {
                                self.last_send_timestamp = Some(ts);
                            }
                        }

                        match self.socket.as_mut().unwrap().send(&packet).await {
                            Err(error) => {
                                warn!(?error, "poll message could not be sent");

                                match error.raw_os_error() {
                                    Some(libc::EHOSTDOWN)
                                    | Some(libc::EHOSTUNREACH)
                                    | Some(libc::ENETDOWN)
                                    | Some(libc::ENETUNREACH) => {
                                        self.channels
                                            .msg_for_system_sender
                                            .send(MsgForSystem::NetworkIssue(self.index))
                                            .await
                                            .ok();
                                        return;
                                    }
                                    _ => {}
                                }
                            }
                            Ok(opt_send_timestamp) => {
                                // update the last_send_timestamp with the one given by the kernel, if available
                                self.last_send_timestamp = opt_send_timestamp
                                    .map(convert_net_timestamp)
                                    .or(self.last_send_timestamp);
                            }
                        }
                    }
                    ntp_proto::GpsSourceAction::UpdateSystem(update) => {
                        self.channels
                            .msg_for_system_sender
                            .send(MsgForSystem::SourceUpdate(self.index, update))
                            .await
                            .ok();
                    }
                    ntp_proto::GpsSourceAction::SetTimer(timeout) => {
                        poll_wait.as_mut().reset(Instant::now() + timeout)
                    }
                    ntp_proto::GpsSourceAction::Reset => {
                        self.channels
                            .msg_for_system_sender
                            .send(MsgForSystem::Unreachable(self.index))
                            .await
                            .ok();
                        return;
                    }
                    ntp_proto::GpsSourceAction::Demobilize => {
                        self.channels
                            .msg_for_system_sender
                            .send(MsgForSystem::MustDemobilize(self.index))
                            .await
                            .ok();
                        return;
                    }
                }
            }
        }
    }
}

impl<C> SourceTask<C, Sleep>
where
    C: 'static + NtpClock + Send + Sync,
{
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(clock, channels))]
    pub fn spawn(
        index: SourceId,
        source_addr: SocketAddr,
        interface: Option<InterfaceName>,
        clock: C,
        timestamp_mode: TimestampMode,
        channels: SourceChannels,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(
            (async move {
               
                let source  = GpsSource::new(source_addr, config_snapshot);
                let poll_wait = tokio::time::sleep(std::time::Duration::default());
                tokio::pin!(poll_wait);



                let mut process = SourceTask {
                    _wait: PhantomData,
                    index,
                    clock,
                    channels,
                    interface,
                    timestamp_mode,
                    source_addr,
                    socket: None,
                    source,
                    last_send_timestamp: None,
                };

                process.run(poll_wait).await;
            })
            .instrument(Span::current()),
        )
    }
}

#[derive(Debug)]
enum AcceptResult<'a> {
    Accept(NtpTimestamp),
    Ignore,
}

fn accept_GPSTime<'a, C: NtpClock>(
    result: Result<GPSData, GPSError>,
) -> AcceptResult<'a> {
    match result {
        Ok(data) => {

            match parse_gps_time(&data) {
                Ok(gps_time) => AcceptResult::Accept(gps_time),
                Err(_) => AcceptResult::Ignore,
            }
        }
        Err(receive_error) => {
            warn!(?receive_error, "could not receive GPS data");

            // Here you might want to handle specific errors from the GPS library,
            // for now we'll just log and ignore them
            AcceptResult::Ignore
        }
    }
}

fn parse_gps_time(data: &GPSData) -> Result<NtpTimestamp, Box<dyn std::error::Error>> {
    // Implement the logic to parse GPS time from the GPSData struct.
    // This is a placeholder implementation.
    let unixTimestamp = match DateTime::parse_from_rfc3339(data.time) {
        Ok(dt) => Some(dt.timestamp() as u64),
        Err(_) => None,
    };

    NtpTimestamp::from_unix_timestamp(unixTimestamp);



    let gps_time = NtpTimestamp::now(); // Replace this with actual parsing logic
    Ok(gps_time)
}

