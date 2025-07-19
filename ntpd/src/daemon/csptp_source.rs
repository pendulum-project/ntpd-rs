use std::{
    io::Cursor,
    net::{Ipv4Addr, SocketAddr},
};

use ntp_proto::{
    CsptpPacket, Measurement, NtpClock, NtpDuration, NtpInstant, NtpTimestamp,
    OneWaySourceSnapshot, OneWaySourceUpdate, ReferenceId, SourceController, SystemSourceUpdate,
    TwoWaySource,
};
use timestamped_socket::{
    interface::InterfaceName,
    socket::{Connected, RecvResult, Socket, open_ip},
};
use tracing::{Instrument, Span, error, instrument, warn};

use crate::daemon::{
    config::TimestampMode,
    exitcode,
    ntp_source::{MsgForSystem, SourceChannels},
    spawn::SourceId,
    util::convert_net_timestamp,
};

#[derive(Debug)]
enum SocketResult {
    Ok,
    Abort,
}

pub(crate) struct CsptpSourceTask<
    C: 'static + NtpClock + Send,
    Controller: SourceController<MeasurementDelay = NtpDuration>,
> {
    index: SourceId,
    clock: C,
    interface: Option<InterfaceName>,
    timestamp_mode: TimestampMode,
    name: String,
    source_addr: SocketAddr,
    socket: Option<Socket<SocketAddr, Connected>>,
    channels: SourceChannels<Controller::ControllerMessage, Controller::SourceMessage>,

    source: TwoWaySource<Controller>,

    last_send_timestamp: Option<NtpTimestamp>,
    seqid: u16,
}

impl<C: 'static + NtpClock + Send, Controller: SourceController<MeasurementDelay = NtpDuration>>
    CsptpSourceTask<C, Controller>
{
    #[allow(clippy::too_many_arguments)]
    #[instrument(level = tracing::Level::ERROR, name = "CSPTP Source", skip(timestamp_mode, clock, channels, source))]
    pub fn spawn(
        index: SourceId,
        name: String,
        source_addr: SocketAddr,
        interface: Option<InterfaceName>,
        clock: C,
        timestamp_mode: TimestampMode,
        channels: SourceChannels<Controller::ControllerMessage, Controller::SourceMessage>,
        source: TwoWaySource<Controller>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(
            (async move {
                let mut process = CsptpSourceTask {
                    index,
                    name,
                    clock,
                    channels,
                    interface,
                    timestamp_mode,
                    source_addr,
                    socket: None,
                    source,
                    last_send_timestamp: None,
                    seqid: 0,
                };

                process.run().await;
            })
            .instrument(Span::current()),
        )
    }

    async fn setup_socket(&mut self) -> SocketResult {
        if self.socket.is_some() {
            return SocketResult::Ok;
        }

        let socket_res = match self.interface {
            #[cfg(target_os = "linux")]
            Some(interface) => {
                use timestamped_socket::socket::open_interface_udp;

                open_interface_udp(
                    interface,
                    319, /*lets os choose*/
                    self.timestamp_mode.as_interface_mode(),
                    None,
                )
                .and_then(|socket| socket.connect(self.source_addr))
            }
            _ => open_ip(
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 319),
                self.timestamp_mode.as_general_mode(),
            )
            .and_then(|socket| socket.connect(self.source_addr)),
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

    async fn run(&mut self) {
        let mut buf = [0u8; 1024];

        let poll_wait = tokio::time::sleep(std::time::Duration::default());
        tokio::pin!(poll_wait);
        let mut poll_wait = poll_wait;

        #[allow(clippy::large_enum_variant)]
        enum SelectResult<Controller: SourceController> {
            Timer,
            Recv(Result<RecvResult<SocketAddr>, std::io::Error>),
            SystemUpdate(
                Result<
                    SystemSourceUpdate<Controller::ControllerMessage>,
                    tokio::sync::broadcast::error::RecvError,
                >,
            ),
        }

        loop {
            let selected: SelectResult<Controller> = tokio::select! {
                () = &mut poll_wait => {
                    SelectResult::Timer
                },
                result = self.channels.system_update_receiver.recv() => {
                    SelectResult::SystemUpdate(result)
                },
                result = async { if let Some(ref mut socket) = self.socket { socket.recv(&mut buf).await } else { std::future::pending().await }} => {
                    SelectResult::Recv(result)
                },
            };

            match selected {
                SelectResult::Timer => {
                    if matches!(self.setup_socket().await, SocketResult::Abort) {
                        self.channels
                            .msg_for_system_sender
                            .send(MsgForSystem::NetworkIssue(self.index))
                            .await
                            .ok();
                        self.channels
                            .source_snapshots
                            .write()
                            .expect("Unexpected poisoned mutex")
                            .remove(&self.index);
                        return;
                    }

                    let mut cursor = Cursor::new(buf.as_mut_slice());
                    self.seqid = self.seqid.wrapping_add(1);
                    let mut tlvbuffer = [0u8; 1024];
                    CsptpPacket::request(&mut tlvbuffer, self.seqid)
                        .serialize(&mut cursor)
                        .unwrap();
                    let packet_size = cursor.position() as usize;
                    let packet = &buf[..packet_size];

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
                                    self.channels
                                        .source_snapshots
                                        .write()
                                        .expect("Unexpected poisoned mutex")
                                        .remove(&self.index);
                                    return;
                                }
                                _ => {}
                            }
                        }
                        Ok(opt_send_timestamp) => {
                            self.channels
                                .source_snapshots
                                .write()
                                .expect("Unexpected poisoned mutex")
                                .insert(
                                    self.index,
                                    self.source.observe(
                                        self.name.clone(),
                                        self.source_addr.to_string(),
                                        self.index,
                                    ),
                                );

                            // update the last_send_timestamp with the one given by the kernel, if available
                            self.last_send_timestamp = opt_send_timestamp
                                .map(convert_net_timestamp)
                                .or(self.last_send_timestamp);
                        }
                    }
                }
                SelectResult::Recv(Ok(RecvResult {
                    bytes_read,
                    timestamp,
                    ..
                })) => {
                    let packet = &buf[..bytes_read];
                    let timestamp = timestamp
                        .map(convert_net_timestamp)
                        .unwrap_or_else(|| self.clock.now().unwrap());

                    let Ok(packet) = CsptpPacket::deserialize(&packet) else {
                        break;
                    };

                    let Some(response_data) = packet.get_csptp_response_data() else {
                        break;
                    };
                    let Some(remote_send_timestamp) = packet.get_origin_timestamp() else {
                        break;
                    };

                    let Some(t1) = self.last_send_timestamp.take() else {
                        break;
                    };
                    let t2 = NtpTimestamp::from_statime(&response_data.req_ingress_timestamp);
                    let t3 = NtpTimestamp::from_statime(&remote_send_timestamp);
                    let t4 = timestamp;

                    let measurement = Measurement {
                        delay: (t4 - t1) - (t3 - t2),
                        offset: ((t2 - t1) + (t3 - t4)) / 2,
                        localtime: t1 + (t4 - t1) / 2,
                        monotime: NtpInstant::now(),
                        stratum: 1,
                        root_delay: NtpDuration::ZERO,
                        root_dispersion: NtpDuration::ZERO,
                        leap: ntp_proto::NtpLeapIndicator::NoWarning,
                        precision: 0,
                    };

                    let update = OneWaySourceUpdate {
                        snapshot: OneWaySourceSnapshot {
                            source_id: ReferenceId::PPS,
                            stratum: 0,
                        },
                        message: self.source.handle_measurement(std::dbg!(measurement)),
                    };

                    self.channels
                        .msg_for_system_sender
                        .send(MsgForSystem::OneWaySourceUpdate(self.index, update))
                        .await
                        .ok();

                    self.channels
                        .source_snapshots
                        .write()
                        .expect("Unexpected poisoned mutex")
                        .insert(
                            self.index,
                            self.source.observe(
                                self.name.clone(),
                                self.source_addr.to_string(),
                                self.index,
                            ),
                        );

                    poll_wait
                        .as_mut()
                        .reset(tokio::time::Instant::now() + std::time::Duration::from_secs(1));
                }
                SelectResult::Recv(Err(_)) => { /* ignore for now */ }
                SelectResult::SystemUpdate(Ok(update)) => {
                    self.source.handle_message(update.message);
                }
                SelectResult::SystemUpdate(Err(_)) => { /* ignore for now */ }
            }
        }
    }
}
