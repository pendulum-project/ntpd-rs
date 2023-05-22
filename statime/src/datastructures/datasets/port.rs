use core::{future::Future, pin::Pin};

use crate::{
    bmc::bmca::RecommendedState,
    datastructures::common::PortIdentity,
    port::{
        state::{MasterState, PortState, SlaveState},
        Ticker,
    },
    time::Duration,
};

/// A concrete implementation of the PTP port dataset (IEEE1588-2019 section
/// 8.2.15)
///
/// The port dataset describes the properties of a single port of the PTP
/// instance. It contains both the ports configuration, as well as a variety of
/// runtime data about the ports current operation.
#[derive(Debug)]
pub struct PortDS {
    pub(crate) port_identity: PortIdentity,
    pub(crate) port_state: PortState,
    log_min_delay_req_interval: i8,
    #[allow(unused)]
    mean_link_delay: Duration,
    log_announce_interval: i8,
    announce_receipt_timeout: u8,
    log_sync_interval: i8,
    #[allow(unused)]
    delay_mechanism: DelayMechanism,
    log_min_p_delay_req_interval: i8,
    #[allow(unused)]
    version_number: u8,
    #[allow(unused)]
    minor_version_number: u8,
    #[allow(unused)]
    delay_asymmetry: Duration,
    port_enable: bool,
    #[allow(unused)]
    master_only: bool,
}

impl PortDS {
    /// Create a new Port dataset
    ///
    /// All `log_*_interval` parameters are the 2-log of the number of seconds
    /// that specific interval should be. The `announce_receipt_timeout` is the
    /// number of announce intervals the port will wait for announce messages
    /// from ptp nodes to show up until automatically becoming master.
    ///
    /// The `log_min_delay_req_interval` and `log_min_p_delay_req_interval`
    /// parameters are used only when their respective delay mechanism is used,
    /// and are ignored otherwise.
    pub fn new(
        port_identity: PortIdentity,
        log_min_delay_req_interval: i8,
        log_announce_interval: i8,
        announce_receipt_timeout: u8,
        log_sync_interval: i8,
        delay_mechanism: DelayMechanism,
        log_min_p_delay_req_interval: i8,
    ) -> Self {
        let mean_link_delay = match delay_mechanism {
            DelayMechanism::E2E | DelayMechanism::NoMechanism | DelayMechanism::Special => {
                Duration::ZERO
            }
            DelayMechanism::P2P | DelayMechanism::CommonP2p => unimplemented!(),
        };

        PortDS {
            port_identity,
            port_state: PortState::Listening,
            log_min_delay_req_interval,
            mean_link_delay,
            log_announce_interval,
            announce_receipt_timeout,
            log_sync_interval,
            delay_mechanism,
            log_min_p_delay_req_interval,
            version_number: 2,
            minor_version_number: 1,
            delay_asymmetry: Duration::ZERO,
            port_enable: true,
            master_only: false,
        }
    }

    pub(crate) fn min_delay_req_interval(&self) -> i8 {
        self.log_min_delay_req_interval
    }

    pub(crate) fn announce_interval(&self) -> Duration {
        Duration::from_log_interval(self.log_announce_interval)
    }

    pub(crate) fn sync_interval(&self) -> Duration {
        Duration::from_log_interval(self.log_sync_interval)
    }

    #[allow(unused)]
    pub(crate) fn min_p_delay_req_interval(&self) -> Duration {
        Duration::from_log_interval(self.log_min_p_delay_req_interval)
    }

    // TODO: Count the actual number of passed announce intervals, rather than this
    // approximation
    pub(crate) fn announce_receipt_interval(&self) -> Duration {
        Duration::from_log_interval(
            self.announce_receipt_timeout as i8 * self.log_announce_interval,
        )
    }

    #[allow(unused)]
    pub(crate) fn disable(&mut self) {
        self.port_enable = false;
        self.set_forced_port_state(PortState::Disabled);
    }

    #[allow(unused)]
    pub(crate) fn enable(&mut self) {
        self.port_enable = true;
        if let PortState::Disabled = self.port_state {
            self.port_state = PortState::Listening;
        }
    }

    pub(crate) fn set_forced_port_state(&mut self, state: PortState) {
        log::info!(
            "new state for port {}: {} -> {}",
            self.port_identity.port_number,
            self.port_state,
            state
        );
        self.port_state = state;
    }

    pub(crate) fn set_recommended_port_state<F: Future>(
        &mut self,
        recommended_state: &RecommendedState,
        announce_receipt_timeout: &mut Pin<&mut Ticker<F, impl FnMut(Duration) -> F>>,
    ) {
        match recommended_state {
            // TODO set things like steps_removed once they are added
            // TODO make sure states are complete
            RecommendedState::S1(announce_message) => {
                let remote_master = announce_message.header().source_port_identity();
                let state = PortState::Slave(SlaveState::new(remote_master));

                match &self.port_state {
                    PortState::Listening | PortState::Master(_) | PortState::Passive => {
                        self.set_forced_port_state(state);
                        announce_receipt_timeout.reset();
                    }
                    PortState::Slave(old_state) => {
                        if old_state.remote_master() != remote_master {
                            self.set_forced_port_state(state);
                            announce_receipt_timeout.reset();
                        }
                    }
                    PortState::Disabled => (),
                }
            }
            RecommendedState::M1(_) | RecommendedState::M2(_) | RecommendedState::M3(_) => {
                match self.port_state {
                    PortState::Listening | PortState::Slave(_) | PortState::Passive => {
                        self.set_forced_port_state(PortState::Master(MasterState::new()))
                    }
                    PortState::Master(_) | PortState::Disabled => (),
                }
            }
            RecommendedState::P1(_) | RecommendedState::P2(_) => match self.port_state {
                PortState::Listening | PortState::Slave(_) | PortState::Master(_) => {
                    self.set_forced_port_state(PortState::Passive)
                }
                PortState::Passive | PortState::Disabled => (),
            },
        }
    }
}

/// Which delay mechanism a port is using.
///
/// Currently, statime only supports the end to end (E2E) delay mechanism.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DelayMechanism {
    /// End to end delay mechanism. Delay measurement is done directly to the
    /// chosen master, across potential transparent nodes in between.
    E2E = 0x01,
    /// Not supported, needed for parsing
    P2P = 0x02,
    /// Not supported, needed for parsing
    NoMechanism = 0xfe,
    /// Not supported, needed for parsing
    CommonP2p = 0x03,
    /// Not supported, needed for parsing
    Special = 0x04,
}
