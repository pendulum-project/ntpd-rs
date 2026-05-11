use ntp_proto::{ClockId, SourceType, TimeSnapshot};
use statime_wire::{ClockIdentity, ClockQuality};

use crate::{
    CsptpState,
    platform::{InternalState, StateMutex},
};

/// General configuration for the CSPTP protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CsptpConfig {
    /// Identity of the local instance.
    pub identity: ClockIdentity,
    /// Priority 1 value to use for the local clock.
    pub priority_1: u8,
    /// Priority 2 value to use for the local clock.
    pub priority_2: u8,
    /// Quality of the local clock.
    pub clock_quality: ClockQuality,
    /// Whether the local time uses the ptp timescale.
    pub ptp_timescale: bool,
    /// Whether the local time is traceable.
    pub time_traceable: bool,
    /// Whether the local frequency is traceable.
    pub frequency_traceable: bool,
}

impl Default for CsptpConfig {
    fn default() -> Self {
        Self {
            identity: ClockIdentity::default(),
            priority_1: 255,
            priority_2: 255,
            clock_quality: ClockQuality::default(),
            ptp_timescale: true,
            time_traceable: false,
            frequency_traceable: false,
        }
    }
}

/// Manager for the CSPTP general protocol state.
pub struct CsptpManager<Mutex> {
    pub(crate) config: CsptpConfig,
    pub(crate) state: Mutex,
}

impl<Mutex: StateMutex> CsptpManager<Mutex> {
    /// Create a new CSPTP protocol manager.
    #[must_use]
    pub fn new(config: CsptpConfig) -> Self {
        Self {
            config,
            state: Mutex::new(InternalState {
                csptp_state: CsptpState {
                    grandmaster_identity: config.identity,
                    grandmaster_priority_1: config.priority_1,
                    grandmaster_priority_2: config.priority_2,
                    grandmaster_clock_quality: config.clock_quality,
                    steps_removed: 0,
                    ptp_timescale: config.ptp_timescale,
                    time_traceable: config.time_traceable,
                    frequency_traceable: config.frequency_traceable,
                },
                time_snapshot: TimeSnapshot::default(),
                active_source: None,
            }),
        }
    }

    /// Update which sources are used for time synchronization.
    pub fn update_used_sources(&self, mut sources: impl Iterator<Item = (ClockId, SourceType)>) {
        let active_source = sources.next().map(|(clock_id, _)| clock_id);
        self.state.with_mut(move |state| {
            if state.active_source != active_source {
                state.active_source = active_source;
                state.csptp_state.grandmaster_identity = self.config.identity;
                state.csptp_state.grandmaster_priority_1 = self.config.priority_1;
                state.csptp_state.grandmaster_priority_2 = self.config.priority_2;
                state.csptp_state.grandmaster_clock_quality = self.config.clock_quality;
                state.csptp_state.ptp_timescale = self.config.ptp_timescale;
                state.csptp_state.time_traceable = self.config.time_traceable;
                state.csptp_state.frequency_traceable = self.config.frequency_traceable;
            }
        });
    }

    /// Observe the system state.
    #[must_use]
    pub fn observe(&self) -> CsptpState {
        self.state.with_ref(|state| state.csptp_state)
    }
}
