use std::time::Duration;
use std::{future::Future, marker::PhantomData, pin::Pin};
use tokio::time::{Instant, Sleep};
use ntp_proto::{NtpClock, NtpInstant, NtpTimestamp, NtpDuration, PpsSource, NtpPacket, NtpLeapIndicator, NtpAssociationMode, ReferenceId};
use tracing::{error, info, instrument, warn, Instrument, Span};
use std::io;
use smoke::mock::*;
use smoke::prelude::*;
use tokio::sync::Mutex;
use std::sync::Arc;

use crate::daemon::ntp_source::MsgForSystem;
use super::{config::TimestampMode, exitcode, ntp_source::SourceChannels, spawn::SourceId, accept_pps_time, from_seconds, PpsSourceTask, Measurement, Pps, AcceptResult, Reach, NtpSource, GpsMeasurement, PollInterval, SystemSnapshot, SourceDefaultsConfig, NtpSourceSnapshot, NtpSourceAction, NtpSourceUpdate};

// Mock implementation for testing
struct MockClock;

impl NtpClock for MockClock {
    fn now(&self) -> Result<NtpTimestamp, std::io::Error> {
        Ok(NtpTimestamp::from_fixed_int(0))
    }

    fn set_freq(&self, _freq: f64) -> Result<(), std::io::Error> {
        Ok(())
    }

    fn step(&self, _duration: std::time::Duration) -> Result<(), std::io::Error> {
        Ok(())
    }

    fn adjust(&self, _offset: std::time::Duration) -> Result<(), std::io::Error> {
        Ok(())
    }
}

// Mock Wait struct for testing
struct MockWait {
    state: Arc<Mutex<Option<Instant>>>,
}

impl MockWait {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(None)),
        }
    }

    fn state(&self) -> Arc<Mutex<Option<Instant>>> {
        self.state.clone()
    }
}

impl Future for MockWait {
    type Output = ();
    
    fn poll(
        self: Pin<&mut Self>, 
        _cx: &mut std::task::Context<'_>
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Ready(())
    }
}

impl Wait for MockWait {
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        let state = self.state.clone();
        tokio::spawn(async move {
            let mut state_guard = state.lock().await;
            *state_guard = Some(deadline);
        });
    }
}

// Mock Pps struct for testing
#[derive(Clone)]
struct MockPps {
    latest_offset: Arc<Mutex<Option<f64>>>,
}

impl MockPps {
    fn new() -> Self {
        Self {
            latest_offset: Arc::new(Mutex::new(None)),
        }
    }

    async fn poll_pps_signal(&self) -> io::Result<Option<(f64, NtpTimestamp)>> {
        let offset = self.latest_offset.lock().await.unwrap_or(0.0);
        let ntp_timestamp = NtpTimestamp::from_fixed_int(0);
        Ok(Some((offset, ntp_timestamp)))
    }
}

#[smoke::test]
async fn test_pps_source_task() {
    let clock = MockClock;
    let pps = MockPps::new();

    let (msg_for_system_sender, mut msg_for_system_receiver) = tokio::sync::mpsc::channel(100);
    let channels = SourceChannels {
        msg_for_system_sender,
        system_snapshot_receiver: tokio::sync::watch::channel(None).1,
    };

    let mut task = PpsSourceTask::<MockClock, MockWait> {
        _wait: PhantomData,
        index: SourceId::new(1),
        clock,
        channels,
        source: PpsSource::new().0,
        last_send_timestamp: None,
        pps,
    };

    let poll_wait = MockWait::new();
    let poll_wait_state = poll_wait.state();
    let pinned_poll_wait = Box::pin(poll_wait);

    tokio::spawn(async move {
        task.run(pinned_poll_wait).await;
    });

    let state_guard = poll_wait_state.lock().await;
    assert!(state_guard.is_some());

    if let Some(MsgForSystem::PpsSourceUpdate(_index, _update)) = msg_for_system_receiver.recv().await {
        assert!(true);
    } else {
        assert!(false, "Expected a PpsSourceUpdate message");
    }
}

#[smoke::test]
async fn test_accept_pps_time_ok() {
    let result = Ok(Some((0.5, NtpTimestamp::from_fixed_int(0))));
    let accept_result = accept_pps_time(result);
    if let AcceptResult::Accept(duration, timestamp) = accept_result {
        assert_eq!(duration, NtpDuration::from_seconds(0.5));
        assert_eq!(timestamp, NtpTimestamp::from_fixed_int(0));
    } else {
        panic!("Expected AcceptResult::Accept");
    }
}

#[smoke::test]
async fn test_accept_pps_time_err() {
    let result: io::Result<Option<(f64, NtpTimestamp)>> = Err(io::Error::new(io::ErrorKind::Other, "Error"));
    let accept_result = accept_pps_time(result);
    if let AcceptResult::Ignore = accept_result {
        assert!(true);
    } else {
        panic!("Expected AcceptResult::Ignore");
    }
}

#[smoke::test]
async fn test_accept_pps_time_none() {
    let result = Ok(None);
    let accept_result = accept_pps_time(result);
    if let AcceptResult::Ignore = accept_result {
        assert!(true);
    } else {
        panic!("Expected AcceptResult::Ignore");
    }
}

#[smoke::test]
async fn test_from_seconds() {
    let seconds = 0.5;
    let duration = from_seconds(seconds);
    assert_eq!(duration, NtpDuration::from_seconds(0.5));
}

#[smoke::test]
async fn test_parse_ppstest_output_valid() {
    let line = "source 0 - assert 1622234567.123456789, sequence: 0";
    if let Some((timestamp, nanos)) = Pps::parse_ppstest_output(line) {
        assert_eq!(timestamp, 1622234567);
        assert_eq!(nanos, 123456789);
    } else {
        panic!("Expected valid timestamp and nanos");
    }
}

#[smoke::test]
async fn test_parse_ppstest_output_invalid() {
    let line = "invalid line format";
    assert!(Pps::parse_ppstest_output(line).is_none());
}

#[smoke::test]
async fn test_measurement_from_packet() {
    let instant = NtpInstant::now();

    let mut packet = NtpPacket::test();
    packet.set_receive_timestamp(NtpTimestamp::from_fixed_int(1));
    packet.set_transmit_timestamp(NtpTimestamp::from_fixed_int(2));
    let result = Measurement::from_packet(
        &packet,
        NtpTimestamp::from_fixed_int(0),
        NtpTimestamp::from_fixed_int(3),
        instant,
        NtpDuration::from_exponent(-32),
    );
    assert_eq!(result.offset, NtpDuration::from_fixed_int(0));
    assert_eq!(result.delay, NtpDuration::from_fixed_int(2));

    packet.set_receive_timestamp(NtpTimestamp::from_fixed_int(2));
    packet.set_transmit_timestamp(NtpTimestamp::from_fixed_int(3));
    let result = Measurement::from_packet(
        &packet,
        NtpTimestamp::from_fixed_int(0),
        NtpTimestamp::from_fixed_int(3),
        instant,
        NtpDuration::from_exponent(-32),
    );
    assert_eq!(result.offset, NtpDuration::from_fixed_int(1));
    assert_eq!(result.delay, NtpDuration::from_fixed_int(2));

    packet.set_receive_timestamp(NtpTimestamp::from_fixed_int(0));
    packet.set_transmit_timestamp(NtpTimestamp::from_fixed_int(5));
    let result = Measurement::from_packet(
        &packet,
        NtpTimestamp::from_fixed_int(0),
        NtpTimestamp::from_fixed_int(3),
        instant,
        NtpDuration::from_exponent(-32),
    );
    assert_eq!(result.offset, NtpDuration::from_fixed_int(1));
    assert_eq!(result.delay, NtpDuration::from_fixed_int(1));
}

#[smoke::test]
async fn reachability() {
    let mut reach = Reach::default();

    assert!(!reach.is_reachable());

    reach.received_packet();
    assert!(reach.is_reachable());

    for _ in 0..7 {
        reach.poll();
    }

    assert!(reach.is_reachable());

    reach.poll();
    assert!(!reach.is_reachable());

    reach.received_packet();
    assert!(reach.is_reachable());
}

#[smoke::test]
async fn test_accept_synchronization() {
    use AcceptSynchronizationError::*;

    let mut source = NtpSource::test_ntp_source();

    #[cfg_attr(not(feature = "ntpv5"), allow(unused_mut))]
    let mut system = SystemSnapshot::default();

    macro_rules! accept {
        () => {{
            let snapshot = NtpSourceSnapshot::from_source(&source);
            snapshot.accept_synchronization(16, &["127.0.0.1".parse().unwrap()], &system)
        }};
    }

    source.source_id = ReferenceId::from_ip("127.0.0.1".parse().unwrap());
    assert_eq!(accept!(), Err(Loop));

    source.source_id = ReferenceId::from_ip("127.0.1.1".parse().unwrap());
    assert_eq!(accept!(), Err(ServerUnreachable));

    source.reach.received_packet();
    assert_eq!(accept!(), Ok(()));

    source.stratum = 42;
    assert_eq!(accept!(), Err(Stratum));
}

#[smoke::test]
async fn test_poll_interval() {
    let mut source = NtpSource::test_ntp_source();
    let mut system = SystemSnapshot::default();

    assert!(source.current_poll_interval(system) >= source.remote_min_poll_interval);
    assert!(source.current_poll_interval(system) >= system.time_snapshot.poll_interval);

    system.time_snapshot.poll_interval = PollIntervalLimits::default().max;
    assert!(source.current_poll_interval(system) >= source.remote_min_poll_interval);
    assert!(source.current_poll_interval(system) >= system.time_snapshot.poll_interval);

    system.time_snapshot.poll_interval = PollIntervalLimits::default().min;
    source.remote_min_poll_interval = PollIntervalLimits::default().max;
    assert!(source.current_poll_interval(system) >= source.remote_min_poll_interval);
    assert!(source.current_poll_interval(system) >= system.time_snapshot.poll_interval);
}

#[smoke::test]
async fn test_handle_incoming() {
    let base = NtpInstant::now();
    let mut source = NtpSource::test_ntp_source();

    let system = SystemSnapshot::default();
    let actions = source.handle_timer(system);
    let mut outgoingbuf = None;
    for action in actions {
        assert!(!matches!(
            action,
            NtpSourceAction::Reset | NtpSourceAction::Demobilize
        ));
        if let NtpSourceAction::Send(buf) = action {
            outgoingbuf = Some(buf);
        }
    }
    let outgoingbuf = outgoingbuf.unwrap();
    let outgoing = NtpPacket::deserialize(&outgoingbuf, &NoCipher).unwrap().0;
    let mut packet = NtpPacket::test();
    let system = SystemSnapshot::default();
    packet.set_stratum(1);
    packet.set_mode(NtpAssociationMode::Server);
    packet.set_origin_timestamp(outgoing.transmit_timestamp());
    packet.set_receive_timestamp(NtpTimestamp::from_fixed_int(100));
    packet.set_transmit_timestamp(NtpTimestamp::from_fixed_int(200));

    let actions = source.handle_incoming(
        system,
        &packet.serialize_without_encryption_vec(None).unwrap(),
        base + Duration::from_secs(1),
        NtpTimestamp::from_fixed_int(0),
        NtpTimestamp::from_fixed_int(400),
    );
    for action in actions {
        assert!(!matches!(
            action,
            NtpSourceAction::Reset
                | NtpSourceAction::Demobilize
                | NtpSourceAction::SetTimer(_)
                | NtpSourceAction::Send(_)
        ));
    }
    let mut actions = source.handle_incoming(
        system,
        &packet.serialize_without_encryption_vec(None).unwrap(),
        base + Duration::from_secs(1),
        NtpTimestamp::from_fixed_int(0),
        NtpTimestamp::from_fixed_int(500),
    );
    assert!(actions.next().is_none());
}

#[smoke::test]
async fn test_startup_unreachable() {
    let mut source = NtpSource::test_ntp_source();
    let system = SystemSnapshot::default();
    let actions = source.handle_timer(system);
    for action in actions {
        assert!(!matches!(
            action,
            NtpSourceAction::Reset | NtpSourceAction::Demobilize
        ));
    }
    let actions = source.handle_timer(system);
    for action in actions {
        assert!(!matches!(
            action,
            NtpSourceAction::Reset | NtpSourceAction::Demobilize
        ));
    }
    let actions = source.handle_timer(system);
    for action in actions {
        assert!(!matches!(
            action,
            NtpSourceAction::Reset | NtpSourceAction::Demobilize
        ));
    }
    let mut actions = source.handle_timer(system);
    assert!(matches!(actions.next(), Some(NtpSourceAction::Reset)));
}

#[smoke::test]
async fn test_running_unreachable() {
    let base = NtpInstant::now();
    let mut source = NtpSource::test_ntp_source();

    let system = SystemSnapshot::default();
    let actions = source.handle_timer(system);
    let mut outgoingbuf = None;
    for action in actions {
        assert!(!matches!(
            action,
            NtpSourceAction::Reset | NtpSourceAction::Demobilize
        ));
        if let NtpSourceAction::Send(buf) = action {
            outgoingbuf = Some(buf);
        }
    }
    let outgoingbuf = outgoingbuf.unwrap();
    let outgoing = NtpPacket::deserialize(&outgoingbuf, &NoCipher).unwrap().0;
    let mut packet = NtpPacket::test();
    let system = SystemSnapshot::default();
    packet.set_stratum(1);
    packet.set_mode(NtpAssociationMode::Server);
    packet.set_origin_timestamp(outgoing.transmit_timestamp());
    packet.set_receive_timestamp(NtpTimestamp::from_fixed_int(100));
    packet.set_transmit_timestamp(NtpTimestamp::from_fixed_int(200));
    let actions = source.handle_incoming(
        system,
        &packet.serialize_without_encryption_vec(None).unwrap(),
        base + Duration::from_secs(1),
        NtpTimestamp::from_fixed_int(0),
        NtpTimestamp::from_fixed_int(400),
    );
    for action in actions {
        assert!(!matches!(
            action,
            NtpSourceAction::Reset
                | NtpSourceAction::Demobilize
                | NtpSourceAction::SetTimer(_)
                | NtpSourceAction::Send(_)
        ));
    }

    let actions = source.handle_timer(system);
    for action in actions {
        assert!(!matches!(
            action,
            NtpSourceAction::Reset | NtpSourceAction::Demobilize
        ));
    }
    let actions = source.handle_timer(system);
    for action in actions {
        assert!(!matches!(
            action,
            NtpSourceAction::Reset | NtpSourceAction::Demobilize
        ));
    }
    let actions = source.handle_timer(system);
    for action in actions {
        assert!(!matches!(
            action,
            NtpSourceAction::Reset | NtpSourceAction::Demobilize
        ));
    }
    let actions = source.handle_timer(system);
    for action in actions {
        assert!(!matches!(
            action,
            NtpSourceAction::Reset | NtpSourceAction::Demobilize
        ));
    }
    let actions = source.handle_timer(system);
    for action in actions {
        assert!(!matches!(
            action,
            NtpSourceAction::Reset | NtpSourceAction::Demobilize
        ));
    }
    let actions = source.handle_timer(system);
    for action in actions {
        assert!(!matches!(
            action,
            NtpSourceAction::Reset | NtpSourceAction::Demobilize
        ));
    }
    let actions = source.handle_timer(system);
    for action in actions {
        assert!(!matches!(
            action,
            NtpSourceAction::Reset | NtpSourceAction::Demobilize
        ));
    }
    let actions = source.handle_timer(system);
    for action in actions {
        assert!(!matches!(
            action,
            NtpSourceAction::Reset | NtpSourceAction::Demobilize
        ));
    }
    let mut actions = source.handle_timer(system);
    assert!(matches!(actions.next(), Some(NtpSourceAction::Reset)));
}

#[smoke::test]
async fn test_stratum_checks() {
    let base = NtpInstant::now();
    let mut source = NtpSource::test_ntp_source();

    let system = SystemSnapshot::default();
    let actions = source.handle_timer(system);
    let mut outgoingbuf = None;
    for action in actions {
        assert!(!matches!(
            action,
            NtpSourceAction::Reset | NtpSourceAction::Demobilize
        ));
        if let NtpSourceAction::Send(buf) = action {
            outgoingbuf = Some(buf);
        }
    }
    let outgoingbuf = outgoingbuf.unwrap();
    let outgoing = NtpPacket::deserialize(&outgoingbuf, &NoCipher).unwrap().0;
    let mut packet = NtpPacket::test();
    let system = SystemSnapshot::default();
    packet.set_stratum(MAX_STRATUM + 1);
    packet.set_mode(NtpAssociationMode::Server);
    packet.set_origin_timestamp(outgoing.transmit_timestamp());
    packet.set_receive_timestamp(NtpTimestamp::from_fixed_int(100));
    packet.set_transmit_timestamp(NtpTimestamp::from_fixed_int(200));
    let mut actions = source.handle_incoming(
        system,
        &packet.serialize_without_encryption_vec(None).unwrap(),
        base + Duration::from_secs(1),
        NtpTimestamp::from_fixed_int(0),
        NtpTimestamp::from_fixed_int(500),
    );
    assert!(actions.next().is_none());

    packet.set_stratum(0);
    let mut actions = source.handle_incoming(
        system,
        &packet.serialize_without_encryption_vec(None).unwrap(),
        base + Duration::from_secs(1),
        NtpTimestamp::from_fixed_int(0),
        NtpTimestamp::from_fixed_int(500),
    );
    assert!(actions.next().is_none());
}

#[smoke::test]
async fn test_handle_kod() {
    let base = NtpInstant::now();
    let mut source = NtpSource::test_ntp_source();

    let mut packet = NtpPacket::test();
    let system = SystemSnapshot::default();
    packet.set_reference_id(ReferenceId::KISS_RSTR);
    packet.set_mode(NtpAssociationMode::Server);
    let mut actions = source.handle_incoming(
        system,
        &packet.serialize_without_encryption_vec(None).unwrap(),
        base + Duration::from_secs(1),
        NtpTimestamp::from_fixed_int(0),
        NtpTimestamp::from_fixed_int(100),
    );
    assert!(actions.next().is_none());

    let mut packet = NtpPacket::test();
    let system = SystemSnapshot::default();
    let actions = source.handle_timer(system);
    let mut outgoingbuf = None;
    for action in actions {
        assert!(!matches!(
            action,
            NtpSourceAction::Reset | NtpSourceAction::Demobilize
        ));
        if let NtpSourceAction::Send(buf) = action {
            outgoingbuf = Some(buf);
        }
    }
    let outgoingbuf = outgoingbuf.unwrap();
    let outgoing = NtpPacket::deserialize(&outgoingbuf, &NoCipher).unwrap().0;
    packet.set_reference_id(ReferenceId::KISS_RSTR);
    packet.set_origin_timestamp(outgoing.transmit_timestamp());
    packet.set_mode(NtpAssociationMode::Server);
    let mut actions = source.handle_incoming(
        system,
        &packet.serialize_without_encryption_vec(None).unwrap(),
        base + Duration::from_secs(1),
        NtpTimestamp::from_fixed_int(0),
        NtpTimestamp::from_fixed_int(100),
    );
    assert!(matches!(actions.next(), Some(NtpSourceAction::Demobilize)));

    let mut packet = NtpPacket::test();
    let system = SystemSnapshot::default();
    packet.set_reference_id(ReferenceId::KISS_DENY);
    packet.set_mode(NtpAssociationMode::Server);
    let mut actions = source.handle_incoming(
        system,
        &packet.serialize_without_encryption_vec(None).unwrap(),
        base + Duration::from_secs(1),
        NtpTimestamp::from_fixed_int(0),
        NtpTimestamp::from_fixed_int(100),
    );
    assert!(actions.next().is_none());

    let mut packet = NtpPacket::test();
    let system = SystemSnapshot::default();
    let actions = source.handle_timer(system);
    let mut outgoingbuf = None;
    for action in actions {
        assert!(!matches!(
            action,
            NtpSourceAction::Reset | NtpSourceAction::Demobilize
        ));
        if let NtpSourceAction::Send(buf) = action {
            outgoingbuf = Some(buf);
        }
    }
    let outgoingbuf = outgoingbuf.unwrap();
    let outgoing = NtpPacket::deserialize(&outgoingbuf, &NoCipher).unwrap().0;
    packet.set_reference_id(ReferenceId::KISS_DENY);
    packet.set_origin_timestamp(outgoing.transmit_timestamp());
    packet.set_mode(NtpAssociationMode::Server);
    let mut actions = source.handle_incoming(
        system,
        &packet.serialize_without_encryption_vec(None).unwrap(),
        base + Duration::from_secs(1),
        NtpTimestamp::from_fixed_int(0),
        NtpTimestamp::from_fixed_int(100),
    );
    assert!(matches!(actions.next(), Some(NtpSourceAction::Demobilize)));

    let old_remote_interval = source.remote_min_poll_interval;
    let mut packet = NtpPacket::test();
    let system = SystemSnapshot::default();
    packet.set_reference_id(ReferenceId::KISS_RATE);
    packet.set_mode(NtpAssociationMode::Server);
    let mut actions = source.handle_incoming(
        system,
        &packet.serialize_without_encryption_vec(None).unwrap(),
        base + Duration::from_secs(1),
        NtpTimestamp::from_fixed_int(0),
        NtpTimestamp::from_fixed_int(100),
    );
    assert!(actions.next().is_none());
    assert_eq!(source.remote_min_poll_interval, old_remote_interval);

    let old_remote_interval = source.remote_min_poll_interval;
    let mut packet = NtpPacket::test();
    let system = SystemSnapshot::default();
    let actions = source.handle_timer(system);
    let mut outgoingbuf = None;
    for action in actions {
        assert!(!matches!(
            action,
            NtpSourceAction::Reset | NtpSourceAction::Demobilize
        ));
        if let NtpSourceAction::Send(buf) = action {
            outgoingbuf = Some(buf);
        }
    }
    let outgoingbuf = outgoingbuf.unwrap();
    let outgoing = NtpPacket::deserialize(&outgoingbuf, &NoCipher).unwrap().0;
    packet.set_reference_id(ReferenceId::KISS_RATE);
    packet.set_origin_timestamp(outgoing.transmit_timestamp());
    packet.set_mode(NtpAssociationMode::Server);
    let mut actions = source.handle_incoming(
        system,
        &packet.serialize_without_encryption_vec(None).unwrap(),
        base + Duration::from_secs(1),
        NtpTimestamp::from_fixed_int(0),
        NtpTimestamp::from_fixed_int(100),
    );
    assert!(actions.next().is_none());
    assert!(source.remote_min_poll_interval >= old_remote_interval);
}
