//! Regression coverage for the controller's frequency accessor.

use statime_algo::{ClockConfig, ControllerConfig, KalmanController, NoAllocKalmanStorage};
use statime_base::{Clock, ClockError, Duration, LeapStatus, TAI, Timestamp};

#[derive(Clone)]
struct TestClock;

impl Clock<TAI> for TestClock {
    fn now(&self) -> Result<Timestamp<TAI>, ClockError> {
        Ok(Timestamp::UNIX_EPOCH)
    }

    fn max_frequency(&self) -> Result<f64, ClockError> {
        Ok(0.5)
    }

    fn get_frequency(&self) -> Result<f64, ClockError> {
        unreachable!()
    }

    fn set_frequency(&self, _: f64) -> Result<Timestamp<TAI>, ClockError> {
        unreachable!()
    }

    fn step_clock(&self, _: Duration) -> Result<Timestamp<TAI>, ClockError> {
        unreachable!()
    }

    fn error_estimate_update(&self, _: Duration, _: Duration) -> Result<(), ClockError> {
        unreachable!()
    }

    fn leap_update(&self, _: LeapStatus) -> Result<(), ClockError> {
        unreachable!()
    }

    fn synchronization_update(&self, _: bool) -> Result<(), ClockError> {
        unreachable!()
    }
}

#[test]
#[allow(clippy::float_cmp, reason = "Exact initial values")]
fn clock_frequency_reports_frequency_estimate() {
    let (controller, clock_id) = KalmanController::<NoAllocKalmanStorage<TestClock, 8>, _>::new(
        TestClock,
        ClockConfig::default(),
        ControllerConfig {
            select_offset_uncertainty_window: 3.0,
            select_link_uncertainty_window: 3.0,
            select_delay_uncertainty_window: 1.0,
            select_max_window_size: 1.0,
            minimum_agreeing_sources: 1,
        },
    )
    .unwrap();

    // Both means start at zero; the distinct variances distinguish the estimates.
    let offset = controller.clock_offset(clock_id).unwrap();
    let frequency = controller.clock_frequency(clock_id).unwrap();
    assert_eq!(offset.value, 0.0);
    assert_eq!(offset.variance, 1e18);
    assert_eq!(frequency.value, 0.0);
    assert_eq!(frequency.variance, 0.25);
}
