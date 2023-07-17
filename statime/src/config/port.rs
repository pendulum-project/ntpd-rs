use crate::{time::Interval, Duration, PortIdentity};

/// Which delay mechanism a port is using.
///
/// Currently, statime only supports the end to end (E2E) delay mechanism.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DelayMechanism {
    /// End to end delay mechanism. Delay measurement is done directly to the
    /// chosen master, across potential transparent nodes in between.
    ///
    /// the interval corresponds to the PortDS logMinDelayReqInterval
    E2E { log_interval: i8 },
    // No support for other delay mechanisms
}

/// Configuration items of the PTP PortDS dataset. Dynamical fields are kept
/// as part of [crate::port::Port].
pub struct PortConfig {
    pub port_identity: PortIdentity,
    pub delay_mechanism: DelayMechanism,
    pub announce_interval: Interval,
    pub announce_receipt_timeout: u8,
    pub sync_interval: Interval,
    pub master_only: bool,
    pub delay_asymmetry: Duration,
    // Notes:
    // Fields specific for delay mechanism are kept as part of [DelayMechanism].
    // Version is always 2.1, so not stored (versionNumber, minorVersionNumber)
}

impl PortConfig {
    pub fn min_delay_req_interval(&self) -> i8 {
        match self.delay_mechanism {
            DelayMechanism::E2E { log_interval } => log_interval,
        }
    }

    pub fn announce_duration(&self) -> core::time::Duration {
        // timeout is the number of announce intervals before the announce expires
        self.announce_interval.as_core_duration() * self.announce_receipt_timeout as u32
    }
}
