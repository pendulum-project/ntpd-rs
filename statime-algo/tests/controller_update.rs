//! Periodic clock control without an asynchronous executor.

use core::future::Future;
use core::pin::{Pin, pin};
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use std::sync::{Arc, Mutex};

use statime_algo::{
    AlgoError, ClockConfig, ControllerConfig, KalmanController, NoAllocKalmanStorage,
};
use statime_base::{Clock, ClockError, Controller, Duration, LeapStatus, TAI, Timestamp};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Failure {
    Read,
    SetFrequency,
}

struct ClockState {
    seconds: u64,
    frequency_calls: usize,
    failure: Option<Failure>,
}

#[derive(Clone)]
struct TestClock(Arc<Mutex<ClockState>>);

impl TestClock {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(ClockState {
            seconds: 10,
            frequency_calls: 0,
            failure: None,
        })))
    }
}

impl Clock<TAI> for TestClock {
    fn now(&self) -> Result<Timestamp<TAI>, ClockError> {
        let state = self.0.lock().unwrap();
        if state.failure == Some(Failure::Read) {
            return Err(ClockError::NoDevice);
        }
        Ok(timestamp(state.seconds))
    }

    fn set_frequency(&self, _: f64) -> Result<Timestamp<TAI>, ClockError> {
        let mut state = self.0.lock().unwrap();
        if state.failure == Some(Failure::SetFrequency) {
            return Err(ClockError::PermissionDenied);
        }
        state.frequency_calls += 1;
        Ok(timestamp(state.seconds))
    }

    fn get_frequency(&self) -> Result<f64, ClockError> {
        Ok(0.0)
    }

    fn max_frequency(&self) -> Result<f64, ClockError> {
        Ok(0.001)
    }

    fn step_clock(&self, _: Duration) -> Result<Timestamp<TAI>, ClockError> {
        panic!("No offset has been observed, so the clock must not step")
    }

    fn error_estimate_update(&self, _: Duration, _: Duration) -> Result<(), ClockError> {
        Ok(())
    }

    fn leap_update(&self, _: LeapStatus) -> Result<(), ClockError> {
        Ok(())
    }

    fn synchronization_update(&self, _: bool) -> Result<(), ClockError> {
        Ok(())
    }
}

type TestController = KalmanController<NoAllocKalmanStorage<TestClock, 8>, TestClock>;

fn timestamp(seconds: u64) -> Timestamp<TAI> {
    Timestamp::from_seconds_nanos_since_unix_epoch(seconds, 0)
}

fn new_controller(clock: &TestClock) -> (TestController, statime_base::ClockId) {
    TestController::new(
        clock.clone(),
        ClockConfig::default(),
        ControllerConfig {
            select_offset_uncertainty_window: 3.0,
            select_link_uncertainty_window: 3.0,
            select_delay_uncertainty_window: 1.0,
            select_max_window_size: 1.0,
            minimum_agreeing_sources: 1,
        },
    )
    .unwrap()
}

#[test]
fn update_progresses_time_without_a_new_measurement() {
    let clock = TestClock::new();
    let (controller, clock_id) = new_controller(&clock);
    clock.0.lock().unwrap().seconds = 11;

    controller.update().unwrap();

    assert_eq!(
        controller
            .clock_snapshot(clock_id)
            .unwrap()
            .root_variance_base_time,
        timestamp(11)
    );
    assert_eq!(clock.0.lock().unwrap().frequency_calls, 1);
}

#[test]
fn update_returns_clock_errors() {
    for (failure, error) in [
        (Failure::Read, ClockError::NoDevice),
        (Failure::SetFrequency, ClockError::PermissionDenied),
    ] {
        let clock = TestClock::new();
        let (controller, clock_id) = new_controller(&clock);
        {
            let mut state = clock.0.lock().unwrap();
            state.seconds = 11;
            state.failure = Some(failure);
        }

        assert_eq!(controller.update(), Err(AlgoError::ClockError(error)));
        assert_eq!(
            controller
                .clock_snapshot(clock_id)
                .unwrap()
                .root_variance_base_time,
            timestamp(10)
        );
        assert_eq!(clock.0.lock().unwrap().frequency_calls, 0);

        clock.0.lock().unwrap().failure = None;
        controller.update().unwrap();
        assert_eq!(clock.0.lock().unwrap().frequency_calls, 1);
    }
}

#[test]
fn update_returns_nonmonotonic_time_error() {
    let clock = TestClock::new();
    let (controller, clock_id) = new_controller(&clock);
    clock.0.lock().unwrap().seconds = 9;

    assert_eq!(
        controller.update(),
        Err(AlgoError::NonMonotonicTimeProgression {
            from: timestamp(10),
            to: timestamp(9),
        })
    );
    assert_eq!(
        controller
            .clock_snapshot(clock_id)
            .unwrap()
            .root_variance_base_time,
        timestamp(10)
    );
    assert_eq!(clock.0.lock().unwrap().frequency_calls, 0);
}

struct Owner(TestController);

impl AsRef<TestController> for Owner {
    fn as_ref(&self) -> &TestController {
        &self.0
    }
}

struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            Poll::Pending
        }
    }
}

struct TestLogger(AtomicUsize);

impl log::Log for TestLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Warn
    }

    fn log(&self, record: &log::Record<'_>) {
        if record.level() == log::Level::Warn
            && record.args().to_string().contains("Could not steer clocks")
        {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn flush(&self) {}
}

#[test]
fn asynchronous_loop_reports_failure_and_retries() {
    static LOGGER: TestLogger = TestLogger(AtomicUsize::new(0));
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Warn);
    let clock = TestClock::new();
    let (controller, _) = new_controller(&clock);
    clock.0.lock().unwrap().failure = Some(Failure::SetFrequency);
    let mut task = pin!(TestController::run(Owner(controller), |_| YieldOnce(false)));
    let mut context = Context::from_waker(Waker::noop());

    assert_eq!(task.as_mut().poll(&mut context), Poll::Pending);
    assert_eq!(LOGGER.0.load(Ordering::Relaxed), 1);
    assert_eq!(clock.0.lock().unwrap().frequency_calls, 0);

    clock.0.lock().unwrap().failure = None;
    assert_eq!(task.as_mut().poll(&mut context), Poll::Pending);
    assert_eq!(LOGGER.0.load(Ordering::Relaxed), 1);
    assert_eq!(clock.0.lock().unwrap().frequency_calls, 1);
}
