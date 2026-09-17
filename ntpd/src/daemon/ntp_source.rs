use std::{
    collections::HashMap, future::Future, marker::PhantomData, net::SocketAddr, pin::Pin, sync::Arc,
};

use ntp_proto::{ClockId, NtpSource, NtpSourceActionIterator, ObservableSourceState};
use statime_base::{Clock, Link, LinkId, TAI, Timestamp};
#[cfg(target_os = "linux")]
use timestamped_socket::socket::open_interface_udp;
use timestamped_socket::{
    interface::InterfaceName,
    socket::{Connected, RecvResult, Socket, connect_address},
};
use tracing::{Instrument, Span, debug, error, instrument, warn};

use tokio::time::{Instant, Sleep};

use crate::daemon::spawn::LinkTerminationReason;

use super::{config::TimestampMode, exitcode};

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
    MustDemobilize(LinkId),
    /// Experienced a network issue and must be restarted
    NetworkIssue(LinkId),
    /// Source is unreachable, and should be restarted with new resolved addr.
    Unreachable(LinkId),
}

#[derive(Debug)]
pub struct SourceChannels {
    pub msg_for_system_sender: tokio::sync::mpsc::Sender<MsgForSystem>,
    pub source_snapshots: Arc<std::sync::RwLock<HashMap<ClockId, ObservableSourceState>>>,
}

pub(crate) struct SourceTask<C: 'static + Clock<TAI> + Send, Controller: Link, T: Wait> {
    _wait: PhantomData<T>,
    link_id: LinkId,
    clock: C,
    interface: Option<InterfaceName>,
    timestamp_mode: TimestampMode,
    name: String,
    source_addr: SocketAddr,
    socket: Option<Socket<SocketAddr, Connected>>,

    source: NtpSource<Controller>,

    // we don't store the real origin timestamp in the packet, because that would leak our
    // system time to the network (and could make attacks easier). So instead there is some
    // garbage data in the origin_timestamp field, and we need to track and pass along the
    // actual origin timestamp ourselves.
    /// Timestamp of the last packet that we sent
    last_send_timestamp: Option<Timestamp<TAI>>,
}

#[derive(Debug)]
enum SocketResult {
    Ok,
    Abort,
}

impl<C, Controller: Link, T> SourceTask<C, Controller, T>
where
    C: 'static + Clock<TAI> + Send + Sync,
    T: Wait,
{
    fn setup_socket(&mut self) -> SocketResult {
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

    async fn run(&mut self, mut poll_wait: Pin<&mut T>) -> LinkTerminationReason {
        loop {
            enum SelectResult {
                Timer,
                Recv(Result<RecvResult<SocketAddr>, std::io::Error>),
            }

            let mut buf = [0_u8; 1024];

            let selected: SelectResult = tokio::select! {
                () = &mut poll_wait => {
                    SelectResult::Timer
                },
                result = async { if let Some(ref mut socket) = self.socket { socket.recv(&mut buf).await } else { std::future::pending().await }} => {
                    SelectResult::Recv(result)
                },
            };

            let actions = match selected {
                SelectResult::Recv(result) => {
                    tracing::debug!("accept packet");
                    match accept_packet(result, &buf, &self.clock) {
                        AcceptResult::Accept(packet, recv_timestamp) => {
                            let Some(send_timestamp) = self.last_send_timestamp else {
                                debug!("we received a message without having sent one; discarding");
                                continue;
                            };

                            self.source
                                .handle_incoming(packet, send_timestamp, recv_timestamp)
                        }
                        AcceptResult::NetworkGone => {
                            return LinkTerminationReason::NetworkIssue;
                        }
                        AcceptResult::Ignore => NtpSourceActionIterator::default(),
                    }
                }
                SelectResult::Timer => {
                    tracing::debug!("wait completed");
                    self.source.handle_timer()
                }
            };

            for action in actions {
                match action {
                    ntp_proto::NtpSourceAction::Send(packet) => {
                        if matches!(self.setup_socket(), SocketResult::Abort) {
                            return LinkTerminationReason::NetworkIssue;
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

                                if let Some(
                                    libc::EHOSTDOWN
                                    | libc::EHOSTUNREACH
                                    | libc::ENETDOWN
                                    | libc::ENETUNREACH,
                                ) = error.raw_os_error()
                                {
                                    return LinkTerminationReason::NetworkIssue;
                                }
                            }
                            Ok(opt_send_timestamp) => {
                                // update the last_send_timestamp with the one given by the kernel, if available
                                self.last_send_timestamp = opt_send_timestamp
                                    .selected_timestamp()
                                    .map(|ts| ts.as_tai(37))
                                    .or(self.last_send_timestamp);
                            }
                        }
                    }
                    ntp_proto::NtpSourceAction::SetTimer(timeout) => {
                        if let Some(deadline) = Instant::now().checked_add(timeout) {
                            // If it overflows, it is so far in the future we may as well not set the timer.
                            poll_wait.as_mut().reset(deadline);
                        }
                    }
                    ntp_proto::NtpSourceAction::Reset => {
                        return LinkTerminationReason::Unreachable;
                    }
                    ntp_proto::NtpSourceAction::Demobilize => {
                        return LinkTerminationReason::MustDemobilize;
                    }
                }
            }
        }
    }
}

impl<C, Controller: Link + Send + 'static> SourceTask<C, Controller, Sleep>
where
    C: 'static + Clock<TAI> + Send + Sync,
{
    #[expect(clippy::too_many_arguments)]
    #[instrument(level = tracing::Level::ERROR, name = "Ntp Source", skip(timestamp_mode, clock, source, initial_actions))]
    pub fn spawn(
        link_id: LinkId,
        name: String,
        source_addr: SocketAddr,
        interface: Option<InterfaceName>,
        clock: C,
        timestamp_mode: TimestampMode,
        source: NtpSource<Controller>,
        initial_actions: NtpSourceActionIterator,
    ) -> tokio::task::JoinHandle<LinkTerminationReason> {
        tokio::spawn(
            (async move {
                let poll_wait = tokio::time::sleep(std::time::Duration::default());
                tokio::pin!(poll_wait);

                for action in initial_actions {
                    match action {
                        ntp_proto::NtpSourceAction::Send(_) => {
                            unreachable!("Should not be sending messages from startup")
                        }
                        ntp_proto::NtpSourceAction::SetTimer(timeout) => {
                            poll_wait.as_mut().reset(Instant::now() + timeout);
                        }
                        ntp_proto::NtpSourceAction::Reset => {
                            unreachable!("Should not be resetting from startup")
                        }
                        ntp_proto::NtpSourceAction::Demobilize => {
                            todo!("Should not be demobilizing from startup")
                        }
                    }
                }

                let mut process = SourceTask {
                    _wait: PhantomData,
                    link_id,
                    name,
                    clock,
                    interface,
                    timestamp_mode,
                    source_addr,
                    socket: None,
                    source,
                    last_send_timestamp: None,
                };

                process.run(poll_wait).await
            })
            .instrument(Span::current()),
        )
    }
}

#[derive(Debug)]
enum AcceptResult<'a> {
    Accept(&'a [u8], Timestamp<TAI>),
    Ignore,
    NetworkGone,
}

fn accept_packet<'a, C: Clock<TAI>>(
    result: Result<RecvResult<SocketAddr>, std::io::Error>,
    buf: &'a [u8],
    clock: &C,
) -> AcceptResult<'a> {
    match result {
        Ok(RecvResult {
            bytes_read: size,
            timestamp_data,
            ..
        }) => {
            let recv_timestamp = timestamp_data.selected_timestamp().map_or_else(
                || match clock.now() {
                    Ok(now) => {
                        debug!(?size, "received a packet without a timestamp, substituting");
                        now
                    }
                    _ => {
                        panic!("Received packet without timestamp and couldn't substitute");
                    }
                },
                |ts| ts.as_tai(37),
            );

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
                Some(libc::EHOSTDOWN | libc::EHOSTUNREACH | libc::ENETDOWN | libc::ENETUNREACH) => {
                    AcceptResult::NetworkGone
                }
                _ => AcceptResult::Ignore,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Cursor,
        net::Ipv4Addr,
        sync::{Arc, RwLock},
        time::Duration,
    };

    use ntp_proto::{
        NoCipher, NtpManager, NtpPacket, NtpServerInfo, ProtocolVersion, SourceConfig,
        SynchronizationConfig,
    };
    use statime_base::{ClockError, LeapStatus, TimeSnapshot};
    use timestamped_socket::socket::{GeneralTimestampMode, Open, open_ip};
    use tokio::sync::mpsc;

    use crate::test::alloc_port;

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

    impl Clock<TAI> for TestClock {
        fn now(&self) -> Result<Timestamp<TAI>, statime_base::ClockError> {
            let cur = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map_err(|_| ClockError::Unknown)?;

            Ok(Timestamp::from_seconds_nanos_since_unix_epoch(
                cur.as_secs(),
                cur.subsec_nanos(),
            ))
        }

        fn set_frequency(&self, _freq: f64) -> Result<Timestamp<TAI>, statime_base::ClockError> {
            unimplemented!()
        }

        fn get_frequency(&self) -> Result<f64, statime_base::ClockError> {
            Ok(0.0)
        }

        fn max_frequency(&self) -> Result<f64, statime_base::ClockError> {
            Ok(500e-6)
        }

        fn step_clock(
            &self,
            _offset: statime_base::Duration,
        ) -> Result<Timestamp<TAI>, statime_base::ClockError> {
            unimplemented!()
        }

        fn error_estimate_update(
            &self,
            _est_error: statime_base::Duration,
            _max_error: statime_base::Duration,
        ) -> Result<(), statime_base::ClockError> {
            unimplemented!()
        }

        fn leap_update(&self, _leap_status: LeapStatus) -> Result<(), statime_base::ClockError> {
            unimplemented!()
        }

        fn synchronization_update(
            &self,
            _synchronized: bool,
        ) -> Result<(), statime_base::ClockError> {
            unimplemented!()
        }
    }

    struct TestController(LinkId);

    impl Link for TestController {
        type Error = std::convert::Infallible;

        fn measurement(
            &self,
            _measurement: statime_base::Measurement,
            _direction: statime_base::Direction,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn external_data_update(
            &self,
            _root_delay: statime_base::Duration,
            _leap_status: Option<LeapStatus>,
            _usable: bool,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn active(&self) -> Result<bool, Self::Error> {
            unimplemented!()
        }

        fn importance(&self) -> Result<Option<f64>, Self::Error> {
            unimplemented!()
        }

        fn desired_poll_interval(&self) -> Result<statime_base::Duration, Self::Error> {
            Ok(statime_base::Duration::from_seconds_nanos(16, 0))
        }

        fn id(&self) -> LinkId {
            self.0
        }
    }

    fn test_startup<T: Wait>() -> (
        SourceTask<TestClock, TestController, T>,
        Socket<SocketAddr, Open>,
    ) {
        let port_base = alloc_port();
        let test_socket = open_ip(
            SocketAddr::from((Ipv4Addr::LOCALHOST, port_base)),
            GeneralTimestampMode::SoftwareRecv,
            false,
        )
        .unwrap();

        let index = ClockId::new();
        let ntp_manager = NtpManager::new(SynchronizationConfig::default(), Arc::new([]));

        let link_id =
            LinkId::new(statime_base::ClockId::new(), statime_base::ClockId::new()).unwrap();

        let (source, _) = ntp_manager.new_source(
            SocketAddr::from((Ipv4Addr::LOCALHOST, port_base)),
            SourceConfig::default(),
            ProtocolVersion::V4,
            TestController(link_id),
            None,
        );

        let process = SourceTask {
            _wait: PhantomData,
            link_id,
            name: "test".into(),
            clock: TestClock {},
            source_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, port_base)),
            interface: None,
            timestamp_mode: TimestampMode::KernelRecv,
            socket: None,
            source,
            last_send_timestamp: None,
        };

        (process, test_socket)
    }

    #[tokio::test]
    async fn test_poll_sends_state_update_and_packet() {
        // Note: Ports must be unique among tests to deal with parallelism
        let (mut process, socket) = test_startup();

        let (poll_wait, poll_send) = TestWait::new();

        let handle = tokio::spawn(async move {
            tokio::pin!(poll_wait);
            process.run(poll_wait).await
        });

        poll_send.notify();

        let mut buf = [0; 48];
        let network = socket.recv(&mut buf).await.unwrap();
        assert_eq!(network.bytes_read, 48);

        handle.abort();
    }

    fn serialize_packet_unencrypted(send_packet: &NtpPacket) -> [u8; 48] {
        let mut buf = [0; 48];
        let mut cursor = Cursor::new(buf.as_mut_slice());
        send_packet.serialize(&mut cursor, &NoCipher, None).unwrap();

        assert_eq!(cursor.position(), 48);

        buf
    }

    #[tokio::test]
    async fn test_timeroundtrip() {
        // Note: Ports must be unique among tests to deal with parallelism
        let (mut process, mut socket) = test_startup();

        let server_info = NtpServerInfo {
            time_snapshot: TimeSnapshot {
                leap_indicator: Some(LeapStatus::None),
                ..Default::default()
            },
            ..Default::default()
        };

        let (poll_wait, poll_send) = TestWait::new();
        let clock = TestClock {};

        let handle = tokio::spawn(async move {
            tokio::pin!(poll_wait);
            process.run(poll_wait).await
        });

        poll_send.notify();

        let mut buf = [0; 48];
        let RecvResult {
            bytes_read: size,
            timestamp_data,
            remote_addr,
            ..
        } = socket.recv(&mut buf).await.unwrap();
        assert_eq!(size, 48);
        let timestamp = timestamp_data.selected_timestamp().unwrap();

        let rec_packet = NtpPacket::deserialize(&buf, &NoCipher).unwrap().0;
        let send_packet =
            NtpPacket::timestamp_response(server_info, rec_packet, timestamp.as_tai(37), &clock);

        let serialized = serialize_packet_unencrypted(&send_packet);
        socket.send_to(&serialized, remote_addr).await.unwrap();

        assert!(!handle.is_finished());

        handle.abort();
    }

    #[tokio::test]
    async fn test_deny_stops_poll() {
        // Note: Ports must be unique among tests to deal with parallelism
        let (mut process, mut socket) = test_startup();

        let (poll_wait, poll_send) = TestWait::new();

        let handle = tokio::spawn(async move {
            tokio::pin!(poll_wait);
            process.run(poll_wait).await
        });

        for _ in 0..3 {
            poll_send.notify();

            let mut buf = [0; 48];
            let RecvResult {
                bytes_read: size,
                timestamp_data,
                remote_addr,
                ..
            } = socket.recv(&mut buf).await.unwrap();
            assert_eq!(size, 48);
            assert!(timestamp_data.selected_timestamp().is_some());

            let rec_packet = NtpPacket::deserialize(&buf, &NoCipher).unwrap().0;
            let send_packet = NtpPacket::deny_response(rec_packet);
            let serialized = serialize_packet_unencrypted(&send_packet);

            socket
                .send_to(&serialized, std::dbg!(remote_addr))
                .await
                .unwrap();

            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        poll_send.notify();

        let status = handle.await.unwrap();
        assert_eq!(status, LinkTerminationReason::MustDemobilize);

        let mut buf = [0; 48];
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(10)) => {/*expected */},
            _ = socket.recv(&mut buf) => { unreachable!("should not receive anything") }
        }
    }
}
