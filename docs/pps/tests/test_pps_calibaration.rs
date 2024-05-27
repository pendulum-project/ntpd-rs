use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::io::Result;
use chrono::{DateTime, NaiveDateTime, Utc};
use docs::pps::pps_calibration::PpsCalibration;

#[test]
fn test_pps_calibration_new() {
    let calibration = PpsCalibration::new();
    assert_eq!(calibration.pps_offset, Duration::from_secs(0));
}

#[test]
fn test_calculate_offset() {
    let mut calibration = PpsCalibration::new();
    let gps_time = SystemTime::now();

    let result = calibration.calculate_offset(gps_time);
    assert!(result.is_ok());
}

#[test]
fn test_apply_offset() {
    let calibration = PpsCalibration::new();
    let timestamp = SystemTime::now();
    let new_timestamp = calibration.apply_offset(timestamp);

    assert_eq!(new_timestamp, timestamp + Duration::from_secs(0));
}