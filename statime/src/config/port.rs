use rand::Rng;

use crate::{time::Interval, Duration};

/// Which delay mechanism a port is using.
///
/// Currently, statime only supports the end to end (E2E) delay mechanism.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum DelayMechanism {
    /// End to end delay mechanism. Delay measurement is done directly to the
    /// chosen master, across potential transparent nodes in between.
    ///
    /// the interval corresponds to the PortDS logMinDelayReqInterval
    E2E { interval: Interval },
    // No support for other delay mechanisms
}

/// Configuration items of the PTP PortDS dataset. Dynamical fields are kept
/// as part of [crate::port::Port].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct PortConfig {
    pub delay_mechanism: DelayMechanism,
    pub announce_interval: Interval,
    // more like announce_message_retries. Specifies how many announce_intervals to wait until the
    // announce message expires.
    pub announce_receipt_timeout: u8,
    pub sync_interval: Interval,
    pub master_only: bool,
    pub delay_asymmetry: Duration,
    // Notes:
    // Fields specific for delay mechanism are kept as part of [DelayMechanism].
    // Version is always 2.1, so not stored (versionNumber, minorVersionNumber)
}

impl PortConfig {
    pub fn min_delay_req_interval(&self) -> Interval {
        match self.delay_mechanism {
            DelayMechanism::E2E { interval } => interval,
        }
    }

    // section 9.2.6.12
    pub fn announce_duration(&self, rng: &mut impl Rng) -> core::time::Duration {
        // add some randomness so that not all timers expire at the same time
        let factor = 1.0 + rng.sample::<f64, _>(rand::distributions::Open01);
        let duration = self.announce_interval.as_core_duration();

        duration.mul_f64(factor * self.announce_receipt_timeout as u32 as f64)
    }
}
