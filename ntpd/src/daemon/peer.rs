use std::{future::Future, marker::PhantomData, net::SocketAddr, pin::Pin};

use ntp_proto::{
    IgnoreReason, Measurement, NtpClock, NtpInstant, NtpTimestamp, Peer, PeerNtsData, PeerSnapshot,
    PollError, ProtocolVersion, SourceDefaultsConfig, SynchronizationConfig, SystemSnapshot,
    Update,
};
use rand::{thread_rng, Rng};
#[cfg(target_os = "linux")]
use timestamped_socket::socket::open_interface_udp;
use timestamped_socket::{
    interface::InterfaceName,
    socket::{connect_address, Connected, RecvResult, Socket},
};
use tracing::{debug, error, info, instrument, warn, Instrument, Span};

use tokio::time::{Instant, Sleep};

use super::{config::TimestampMode, exitcode, spawn::PeerId, util::convert_net_timestamp};

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
pub enum MsgForSystem {
    /// Received a Kiss-o'-Death and must demobilize
    MustDemobilize(PeerId),
    /// Experienced a network issue and must be restarted
    NetworkIssue(PeerId),
    /// Source is unreachable, and should be restarted with new resolved addr.
    Unreachable(PeerId),
    /// Received an acceptable packet and made a new peer snapshot
    /// A new measurement should try to trigger a clock select
    NewMeasurement(PeerId, PeerSnapshot, Measurement),
    /// A snapshot may have been updated, but this should not
    /// trigger a clock select in System
    UpdatedSnapshot(PeerId, PeerSnapshot),
}

#[derive(Debug, Clone)]
pub struct PeerChannels {
    pub msg_for_system_sender: tokio::sync::mpsc::Sender<MsgForSystem>,
    pub system_snapshot_receiver: tokio::sync::watch::Receiver<SystemSnapshot>,
    pub synchronization_config_receiver: tokio::sync::watch::Receiver<SynchronizationConfig>,
    pub source_defaults_config_receiver: tokio::sync::watch::Receiver<SourceDefaultsConfig>,
}

pub(crate) struct PeerTask<C: 'static + NtpClock + Send, T: Wait> {
    _wait: PhantomData<T>,
    index: PeerId,
    clock: C,
    socket: Socket<SocketAddr, Connected>,
    channels: PeerChannels,

    peer: Peer,

    // we don't store the real origin timestamp in the packet, because that would leak our
    // system time to the network (and could make attacks easier). So instead there is some
    // garbage data in the origin_timestamp field, and we need to track and pass along the
    // actual origin timestamp ourselves.
    /// Timestamp of the last packet that we sent
    last_send_timestamp: Option<NtpTimestamp>,

    /// Instant last poll message was sent (used for timing the wait)
    last_poll_sent: Instant,
}

#[derive(Debug)]
enum PollResult {
    Ok,
    NetworkGone,
    Unreachable,
}

#[derive(Debug)]
enum PacketResult {
    Ok,
    Demobilize,
}

impl<C, T> PeerTask<C, T>
where
    C: 'static + NtpClock + Send + Sync,
    T: Wait,
{
    /// Set the next deadline for the poll interval based on current state
    fn update_poll_wait(&self, poll_wait: &mut Pin<&mut T>, system_snapshot: SystemSnapshot) {
        let poll_interval = self
            .peer
            .current_poll_interval(system_snapshot)
            .as_system_duration();

        // randomize the poll interval a little to make it harder to predict poll requests
        let poll_interval = poll_interval.mul_f64(thread_rng().gen_range(1.01..=1.05));

        poll_wait
            .as_mut()
            .reset(self.last_poll_sent + poll_interval);
    }

    async fn handle_poll(&mut self, poll_wait: &mut Pin<&mut T>) -> PollResult {
        let system_snapshot = *self.channels.system_snapshot_receiver.borrow();
        let peer_defaults_snapshot_system = *self
            .channels
            .source_defaults_config_receiver
            .borrow_and_update();

        let mut buf = [0; 1024];
        let packet = match self.peer.generate_poll_message(
            &mut buf,
            system_snapshot,
            &peer_defaults_snapshot_system,
        ) {
            Ok(packet) => packet,
            Err(PollError::Io(e)) => {
                warn!(error = ?e, "Could not generate poll message");
                // not exactly a network gone situation, but needs the same response
                return PollResult::NetworkGone;
            }
            Err(PollError::PeerUnreachable) => {
                warn!("Peer is no longer reachable over network, restarting");
                return PollResult::Unreachable;
            }
        };

        // Sent a poll, so update waiting to match deadline of next
        self.last_poll_sent = Instant::now();
        self.update_poll_wait(poll_wait, system_snapshot);

        // the last_send_timestamp is only None at startup
        let is_first_snapshot = self.last_send_timestamp.is_none();

        // The first snapshot does not contain useful data (stratum is invalid)
        // Skipping the message prevents confusing log messages from being emitted.
        if !is_first_snapshot {
            // NOTE: fitness check is not performed here, but by System
            let snapshot = PeerSnapshot::from_peer(&self.peer);
            let msg = MsgForSystem::UpdatedSnapshot(self.index, snapshot);
            self.channels.msg_for_system_sender.send(msg).await.ok();
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

        match self.socket.send(packet).await {
            Err(error) => {
                warn!(?error, "poll message could not be sent");

                match error.raw_os_error() {
                    Some(libc::EHOSTDOWN)
                    | Some(libc::EHOSTUNREACH)
                    | Some(libc::ENETDOWN)
                    | Some(libc::ENETUNREACH) => return PollResult::NetworkGone,
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

        PollResult::Ok
    }

    async fn handle_packet<'a>(
        &mut self,
        poll_wait: &mut Pin<&mut T>,
        packet: &'a [u8],
        send_timestamp: NtpTimestamp,
        recv_timestamp: NtpTimestamp,
    ) -> PacketResult {
        let ntp_instant = NtpInstant::now();

        let system_snapshot = *self.channels.system_snapshot_receiver.borrow();
        let result = self.peer.handle_incoming(
            system_snapshot,
            packet,
            ntp_instant,
            send_timestamp,
            recv_timestamp,
        );

        // Handle incoming may have changed poll interval based on message, respect that change
        self.update_poll_wait(poll_wait, system_snapshot);

        match result {
            Ok(update) => {
                debug!("packet accepted");

                // NOTE: fitness check is not performed here, but by System

                let msg = match update {
                    Update::BareUpdate(update) => MsgForSystem::UpdatedSnapshot(self.index, update),
                    Update::NewMeasurement(update, measurement) => {
                        MsgForSystem::NewMeasurement(self.index, update, measurement)
                    }
                };
                self.channels.msg_for_system_sender.send(msg).await.ok();
            }
            Err(IgnoreReason::KissDemobilize) => {
                info!("Demobilizing peer connection on request of remote.");
                let msg = MsgForSystem::MustDemobilize(self.index);
                self.channels.msg_for_system_sender.send(msg).await.ok();

                return PacketResult::Demobilize;
            }
            Err(ignore_reason) => {
                debug!(?ignore_reason, "packet ignored");
            }
        }

        PacketResult::Ok
    }

    async fn run(&mut self, mut poll_wait: Pin<&mut T>) {
        loop {
            let mut buf = [0_u8; 1024];

            tokio::select! {
                () = &mut poll_wait => {
                    tracing::debug!("wait completed");
                    match self.handle_poll(&mut poll_wait).await {
                        PollResult::Ok => {},
                        PollResult::NetworkGone => {
                            self.channels.msg_for_system_sender.send(MsgForSystem::NetworkIssue(self.index)).await.ok();
                            break;
                        }
                        PollResult::Unreachable => {
                            self.channels.msg_for_system_sender.send(MsgForSystem::Unreachable(self.index)).await.ok();
                            break;
                        }
                    }
                },
                result = self.socket.recv(&mut buf) => {
                    tracing::debug!("accept packet");
                    match accept_packet(result, &buf, &self.clock) {
                        AcceptResult::Accept(packet, recv_timestamp) => {
                            let send_timestamp = match self.last_send_timestamp {
                                Some(ts) => ts,
                                None => {
                                    debug!("we received a message without having sent one; discarding");
                                    continue;
                                }
                            };

                            match self.handle_packet(&mut poll_wait, packet, send_timestamp, recv_timestamp).await {
                                PacketResult::Ok => {},
                                PacketResult::Demobilize => break,
                            }
                        },
                        AcceptResult::NetworkGone => {
                            self.channels.msg_for_system_sender.send(MsgForSystem::NetworkIssue(self.index)).await.ok();
                            break;
                        },
                        AcceptResult::Ignore => {},
                    }
                },
                _ = self.channels.synchronization_config_receiver.changed(), if self.channels.synchronization_config_receiver.has_changed().is_ok() => {
                    self.peer.update_config(*self.channels.source_defaults_config_receiver.borrow_and_update());
                },
            }
        }
    }
}

impl<C> PeerTask<C, Sleep>
where
    C: 'static + NtpClock + Send + Sync,
{
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(clock, channels))]
    pub fn spawn(
        index: PeerId,
        addr: SocketAddr,
        interface: Option<InterfaceName>,
        clock: C,
        timestamp_mode: TimestampMode,
        network_wait_period: std::time::Duration,
        mut channels: PeerChannels,
        protocol_version: ProtocolVersion,
        nts: Option<Box<PeerNtsData>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(
            (async move {
                let socket_res = match interface {
                    #[cfg(target_os = "linux")]
                    Some(interface) => {
                        open_interface_udp(
                            interface,
                            0, /*lets os choose*/
                            timestamp_mode.as_interface_mode(),
                            None,
                        )
                        .and_then(|socket| socket.connect(addr))
                    }
                    _ => connect_address(addr, timestamp_mode.as_general_mode()),
                };

                let socket = match socket_res {
                    Ok(socket) => socket,
                    Err(error) => {
                        warn!(?error, "Could not open socket");
                        tokio::time::sleep(network_wait_period).await;
                        channels
                            .msg_for_system_sender
                            .send(MsgForSystem::NetworkIssue(index))
                            .await
                            .ok();
                        return;
                    }
                };
                // Unwrap should be safe because we know the socket was bound to a local addres just before
                let our_addr = socket.local_addr().unwrap();

                // Unwrap should be safe because we know the socket was connected to a remote peer just before
                let source_addr = socket.peer_addr().unwrap();

                let local_clock_time = NtpInstant::now();
                let config_snapshot = *channels.source_defaults_config_receiver.borrow_and_update();
                let peer = if let Some(nts) = nts {
                    Peer::new_nts(
                        our_addr,
                        source_addr,
                        local_clock_time,
                        config_snapshot,
                        protocol_version,
                        nts,
                    )
                } else {
                    Peer::new(
                        our_addr,
                        source_addr,
                        local_clock_time,
                        config_snapshot,
                        protocol_version,
                    )
                };

                let poll_wait = tokio::time::sleep(std::time::Duration::default());
                tokio::pin!(poll_wait);

                let mut process = PeerTask {
                    _wait: PhantomData,
                    index,
                    clock,
                    channels,
                    socket,
                    peer,
                    last_send_timestamp: None,
                    last_poll_sent: Instant::now(),
                };

                process.run(poll_wait).await;
            })
            .instrument(Span::current()),
        )
    }
}

#[derive(Debug)]
enum AcceptResult<'a> {
    Accept(&'a [u8], NtpTimestamp),
    Ignore,
    NetworkGone,
}

fn accept_packet<'a, C: NtpClock>(
    result: Result<RecvResult<SocketAddr>, std::io::Error>,
    buf: &'a [u8],
    clock: &C,
) -> AcceptResult<'a> {
    match result {
        Ok(RecvResult {
            bytes_read: size,
            timestamp,
            ..
        }) => {
            let recv_timestamp = timestamp.map(convert_net_timestamp).unwrap_or_else(|| {
                if let Ok(now) = clock.now() {
                    debug!(?size, "received a packet without a timestamp, substituting");
                    now
                } else {
                    panic!("Received packet without timestamp and couldn't substitute");
                }
            });

            // Note: packets are allowed to be bigger when including extensions.
            // we don't expect them, but the server may still send them. The
            // extra bytes are guaranteed safe to ignore. `recv` truncates the messages.
            // Messages of fewer than 48 bytes are skipped entirely
            if size < 48 {
                debug!(expected = 48, actual = size, "received packet is too small");

                AcceptResult::Ignore
            } else {
                AcceptResult::Accept(&buf[0..size], recv_timestamp)
            }
        }
        Err(receive_error) => {
            warn!(?receive_error, "could not receive packet");

            match receive_error.raw_os_error() {
                Some(libc::EHOSTDOWN)
                | Some(libc::EHOSTUNREACH)
                | Some(libc::ENETDOWN)
                | Some(libc::ENETUNREACH) => AcceptResult::NetworkGone,
                _ => AcceptResult::Ignore,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, net::Ipv4Addr, sync::Arc, time::Duration};

    use ntp_proto::{NoCipher, NtpDuration, NtpLeapIndicator, NtpPacket, TimeSnapshot};
    use timestamped_socket::socket::{open_ip, GeneralTimestampMode};
    use tokio::sync::mpsc;

    use crate::daemon::util::EPOCH_OFFSET;

    use super::*;

    struct TestWaitSender {
        state: Arc<std::sync::Mutex<TestWaitState>>,
    }

    impl TestWaitSender {
        fn notify(&self) {
            let mut state = self.state.lock().unwrap();
            state.pending = true;
            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
        }
    }

    struct TestWait {
        state: Arc<std::sync::Mutex<TestWaitState>>,
    }

    struct TestWaitState {
        waker: Option<std::task::Waker>,
        pending: bool,
    }

    impl Future for TestWait {
        type Output = ();

        fn poll(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            let mut state = self.state.lock().unwrap();

            if state.pending {
                state.pending = false;
                state.waker = None;
                std::task::Poll::Ready(())
            } else {
                state.waker = Some(cx.waker().clone());
                std::task::Poll::Pending
            }
        }
    }

    impl Wait for TestWait {
        fn reset(self: Pin<&mut Self>, _deadline: Instant) {}
    }

    impl Drop for TestWait {
        fn drop(&mut self) {
            self.state.lock().unwrap().waker = None;
        }
    }

    impl TestWait {
        fn new() -> (TestWait, TestWaitSender) {
            let state = Arc::new(std::sync::Mutex::new(TestWaitState {
                waker: None,
                pending: false,
            }));

            (
                TestWait {
                    state: state.clone(),
                },
                TestWaitSender { state },
            )
        }
    }

    #[derive(Debug, Clone, Default)]
    struct TestClock {}

    impl NtpClock for TestClock {
        type Error = std::time::SystemTimeError;

        fn now(&self) -> std::result::Result<NtpTimestamp, Self::Error> {
            let cur =
                std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH)?;

            Ok(NtpTimestamp::from_seconds_nanos_since_ntp_era(
                EPOCH_OFFSET.wrapping_add(cur.as_secs() as u32),
                cur.subsec_nanos(),
            ))
        }

        fn set_frequency(&self, _freq: f64) -> Result<NtpTimestamp, Self::Error> {
            panic!("Shouldn't be called by peer");
        }

        fn step_clock(&self, _offset: NtpDuration) -> Result<NtpTimestamp, Self::Error> {
            panic!("Shouldn't be called by peer");
        }

        fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by peer");
        }

        fn error_estimate_update(
            &self,
            _est_error: NtpDuration,
            _max_error: NtpDuration,
        ) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by peer");
        }

        fn status_update(&self, _leap_status: NtpLeapIndicator) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by peer");
        }
    }

    async fn test_startup<T: Wait>(
        port_base: u16,
    ) -> (
        PeerTask<TestClock, T>,
        Socket<SocketAddr, Connected>,
        mpsc::Receiver<MsgForSystem>,
    ) {
        // Note: Ports must be unique among tests to deal with parallelism, hence
        // port_base
        let socket = open_ip(
            SocketAddr::from((Ipv4Addr::LOCALHOST, port_base)),
            GeneralTimestampMode::SoftwareRecv,
        )
        .unwrap();
        let socket = socket
            .connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port_base + 1)))
            .unwrap();

        let test_socket = open_ip(
            SocketAddr::from((Ipv4Addr::LOCALHOST, port_base + 1)),
            GeneralTimestampMode::SoftwareRecv,
        )
        .unwrap();
        let test_socket = test_socket
            .connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port_base)))
            .unwrap();
        let our_addr = socket.local_addr().unwrap();
        let source_addr = socket.peer_addr().unwrap();

        let (_, system_snapshot_receiver) = tokio::sync::watch::channel(SystemSnapshot::default());
        let (_, synchronization_config_receiver) =
            tokio::sync::watch::channel(SynchronizationConfig::default());
        let (_, mut peer_defaults_config_receiver) =
            tokio::sync::watch::channel(SourceDefaultsConfig::default());
        let (msg_for_system_sender, msg_for_system_receiver) = mpsc::channel(1);

        let local_clock_time = NtpInstant::now();
        let peer = Peer::new(
            our_addr,
            source_addr,
            local_clock_time,
            *peer_defaults_config_receiver.borrow_and_update(),
            ProtocolVersion::default(),
        );

        let process = PeerTask {
            _wait: PhantomData,
            index: PeerId::new(),
            clock: TestClock {},
            channels: PeerChannels {
                msg_for_system_sender,
                system_snapshot_receiver,
                synchronization_config_receiver,
                source_defaults_config_receiver: peer_defaults_config_receiver,
            },
            socket,
            peer,
            last_send_timestamp: None,
            last_poll_sent: Instant::now(),
        };

        (process, test_socket, msg_for_system_receiver)
    }

    #[tokio::test]
    async fn test_poll_sends_state_update_and_packet() {
        // Note: Ports must be unique among tests to deal with parallelism
        let (mut process, socket, _) = test_startup(8006).await;

        let (poll_wait, poll_send) = TestWait::new();

        let handle = tokio::spawn(async move {
            tokio::pin!(poll_wait);
            process.run(poll_wait).await;
        });

        poll_send.notify();

        let mut buf = [0; 48];
        let network = socket.recv(&mut buf).await.unwrap();
        assert_eq!(network.bytes_read, 48);

        handle.abort();
    }

    fn serialize_packet_unencryped(send_packet: &NtpPacket) -> [u8; 48] {
        let mut buf = [0; 48];
        let mut cursor = Cursor::new(buf.as_mut_slice());
        send_packet.serialize(&mut cursor, &NoCipher, None).unwrap();

        assert_eq!(cursor.position(), 48);

        buf
    }

    #[tokio::test]
    async fn test_timeroundtrip() {
        // Note: Ports must be unique among tests to deal with parallelism
        let (mut process, mut socket, mut msg_recv) = test_startup(8008).await;

        let system = SystemSnapshot {
            time_snapshot: TimeSnapshot {
                leap_indicator: NtpLeapIndicator::NoWarning,
                ..Default::default()
            },
            ..Default::default()
        };

        let (poll_wait, poll_send) = TestWait::new();
        let clock = TestClock {};

        let handle = tokio::spawn(async move {
            tokio::pin!(poll_wait);
            process.run(poll_wait).await;
        });

        poll_send.notify();

        let mut buf = [0; 48];
        let RecvResult {
            bytes_read: size,
            timestamp,
            ..
        } = socket.recv(&mut buf).await.unwrap();
        assert_eq!(size, 48);
        let timestamp = timestamp.unwrap();

        let rec_packet = NtpPacket::deserialize(&buf, &NoCipher).unwrap().0;
        let send_packet = NtpPacket::timestamp_response(
            &system,
            rec_packet,
            convert_net_timestamp(timestamp),
            &clock,
        );

        let serialized = serialize_packet_unencryped(&send_packet);
        socket.send(&serialized).await.unwrap();

        let msg = msg_recv.recv().await.unwrap();
        assert!(matches!(msg, MsgForSystem::NewMeasurement(_, _, _)));

        handle.abort();
    }

    #[tokio::test]
    async fn test_deny_stops_poll() {
        // Note: Ports must be unique among tests to deal with parallelism
        let (mut process, mut socket, mut msg_recv) = test_startup(8010).await;

        let (poll_wait, poll_send) = TestWait::new();

        let handle = tokio::spawn(async move {
            tokio::pin!(poll_wait);
            process.run(poll_wait).await;
        });

        poll_send.notify();

        let mut buf = [0; 48];
        let RecvResult {
            bytes_read: size,
            timestamp,
            ..
        } = socket.recv(&mut buf).await.unwrap();
        assert_eq!(size, 48);
        assert!(timestamp.is_some());

        let rec_packet = NtpPacket::deserialize(&buf, &NoCipher).unwrap().0;
        let send_packet = NtpPacket::deny_response(rec_packet);
        let serialized = serialize_packet_unencryped(&send_packet);

        socket.send(&serialized).await.unwrap();

        let msg = msg_recv.recv().await.unwrap();
        assert!(matches!(msg, MsgForSystem::MustDemobilize(_)));

        poll_send.notify();

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(10)) => {/*expected */},
            _ = socket.recv(&mut buf) => { unreachable!("should not receive anything") }
        }

        handle.abort();
    }
}
