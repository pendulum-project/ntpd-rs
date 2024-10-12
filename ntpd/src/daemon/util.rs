use ntp_proto::NtpTimestamp;

// Epoch offset between NTP and UNIX timescales
pub(crate) const EPOCH_OFFSET: u32 = (70 * 365 + 17) * 86400;

#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_sign_loss)]
pub(crate) fn convert_net_timestamp(ts: timestamped_socket::socket::Timestamp) -> NtpTimestamp {
    NtpTimestamp::from_seconds_nanos_since_ntp_era(
        EPOCH_OFFSET.wrapping_add(ts.seconds as _),
        ts.nanos,
    )
}

#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_sign_loss)]
pub(crate) fn convert_clock_timestamp(ts: clock_steering::Timestamp) -> NtpTimestamp {
    NtpTimestamp::from_seconds_nanos_since_ntp_era(
        EPOCH_OFFSET.wrapping_add(ts.seconds as _),
        ts.nanos,
    )
}
