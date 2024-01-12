use ntp_proto::NtpTimestamp;
use timestamped_socket::socket::Timestamp;

// Epoch offset between NTP and UNIX timescales
pub(crate) const EPOCH_OFFSET: u32 = (70 * 365 + 17) * 86400;

pub(crate) fn convert_timestamp(ts: Timestamp) -> NtpTimestamp {
    NtpTimestamp::from_seconds_nanos_since_ntp_era(
        EPOCH_OFFSET.wrapping_add(ts.seconds as _),
        ts.nanos,
    )
}
