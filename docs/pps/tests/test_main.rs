use super::*;

#[test]
fn test_ntp_duration_from_bits() {
    let bits = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
    let duration = NtpDuration::from_bits(bits);
    assert_eq!(duration.duration, 256);
}

#[test]
fn test_ntp_duration_from_bits_short() {
    let bits = [0x00, 0x00, 0x01, 0x00];
    let duration = NtpDuration::from_bits_short(bits);
    assert_eq!(duration.duration, 16777216); 
}

#[test]
fn test_ntp_duration_to_seconds() {
    let duration = NtpDuration { duration: 4294967296 }; 
    assert!((duration.to_seconds() - 1.0).abs() < 1e-9);
}

#[test]
fn test_ntp_duration_from_seconds() {
    let duration = NtpDuration::from_seconds(1.0);
    assert_eq!(duration.duration, 4294967296); 
}

#[test]
fn test_ntp_duration_abs() {
    let duration = NtpDuration { duration: -5 };
    assert_eq!(duration.abs().duration, 5);
}

#[test]
fn test_ntp_duration_abs_diff() {
    let duration1 = NtpDuration { duration: 10 };
    let duration2 = NtpDuration { duration: 2 };
    assert_eq!(duration1.abs_diff(duration2).duration, 8);
}

#[test]
fn test_ntp_duration_as_seconds_nanos() {
    let duration = NtpDuration { duration: 4294967296 }; 
    assert_eq!(duration.as_seconds_nanos(), (1, 0));
}

#[test]
fn test_ntp_duration_from_exponent() {
    let duration = NtpDuration::from_exponent(3);
    assert_eq!(duration.duration, 34359738368); 
}

#[test]
fn test_ntp_duration_log2() {
    let duration = NtpDuration { duration: 4294967296 }; 
    assert_eq!(duration.log2(), Some(32)); 

    let duration = NtpDuration { duration: 1 }; 
    assert_eq!(duration.log2(), Some(0)); 

    let duration = NtpDuration { duration: 2 }; 
    assert_eq!(duration.log2(), Some(1)); 

    let duration = NtpDuration { duration: 16 }; 
    assert_eq!(duration.log2(), Some(4)); 

    let duration = NtpDuration { duration: 0 }; 
    assert_eq!(duration.log2(), None); 
}

#[test]
fn test_ntp_duration_from_system_duration() {
    let system_duration = Duration::new(1, 0);
    let ntp_duration = NtpDuration::from_system_duration(system_duration);
    assert_eq!(ntp_duration.duration, 4294967296); 
}

#[test]
fn test_ntp_duration_sub() {
    let duration1 = NtpDuration { duration: 8 };
    let duration2 = NtpDuration { duration: 2 };
    assert_eq!((duration1 - duration2).duration, 6);
}

// NtpTimestamp Tests:
#[test]
fn test_ntp_timestamp_from_bits() {
    let bits = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
    let timestamp = NtpTimestamp::from_bits(bits);
    assert_eq!(timestamp.timestamp, 256);
}

#[test]
fn test_ntp_timestamp_to_bits() {
    let timestamp = NtpTimestamp { timestamp: 256 };
    assert_eq!(timestamp.to_bits(), [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);
}

#[test]
fn test_ntp_timestamp_from_seconds_nanos_since_ntp_era() {
    let timestamp = NtpTimestamp::from_seconds_nanos_since_ntp_era(1, 0);
    assert_eq!(timestamp.timestamp, 1u64 << 32);

    let timestamp = NtpTimestamp::from_seconds_nanos_since_ntp_era(1, 500000000);
    assert_eq!(timestamp.timestamp, (1u64 << 32) + (1u64 << 31));

    let timestamp = NtpTimestamp::from_seconds_nanos_since_ntp_era(0, 500000000);
    assert_eq!(timestamp.timestamp, 1u64 << 31);

    let timestamp = NtpTimestamp::from_seconds_nanos_since_ntp_era(0, 0);
    assert_eq!(timestamp.timestamp, 0);
}

#[test]
fn test_ntp_timestamp_from_unix_timestamp() {
    let timestamp = NtpTimestamp::from_unix_timestamp(1620000000, 0);
    assert_eq!(timestamp.timestamp, 3828988800u64 << 32);

    let timestamp = NtpTimestamp::from_unix_timestamp(1620000000, 500000000);
    assert_eq!(timestamp.timestamp, (3828988800u64 << 32) + (1u64 << 31));

    let timestamp = NtpTimestamp::from_unix_timestamp(0, 500000000);
    assert_eq!(timestamp.timestamp, (2208988800u64 << 32) + (1u64 << 31));

    let timestamp = NtpTimestamp::from_unix_timestamp(0, 0);
    assert_eq!(timestamp.timestamp, 2208988800u64 << 32);
}

#[test]
fn test_ntp_timestamp_sub() {
    let timestamp1 = NtpTimestamp { timestamp: 9 };
    let timestamp2 = NtpTimestamp { timestamp: 7 };
    let duration = timestamp1 - timestamp2;
    assert_eq!(duration.duration, 2);
}