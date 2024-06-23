use crate::time_types::{NtpInstant};
use crate::source::Measurement;
use crate::{NtpDuration, NtpTimestamp};
use std::time::Duration;

use tracing::{instrument, warn};

#[derive(Debug)]
pub struct PpsSource {

}

#[derive(Debug, Copy, Clone)]
pub struct PpsSourceUpdate {
    pub(crate) measurement: Option<Measurement>,
}

#[cfg(feature = "__internal-test")]
impl PpsSourceUpdate {
    pub fn measurement(measurement: Measurement) -> Self {
        PpsSourceUpdate {
            measurement: Some(measurement),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum PpsSourceAction {
    /// Send a message over the network. When this is issued, the network port maybe changed.
    Send(),
    /// Send an update to [`System`](crate::system::System)
    UpdateSystem(PpsSourceUpdate),
    /// Call [`NtpSource::handle_timer`] after given duration
    SetTimer(Duration),
    /// A complete reset of the connection is necessary, including a potential new NTSKE client session and/or DNS lookup.
    Reset,
    /// We must stop talking to this particular server.
    Demobilize,
}

#[derive(Debug)]
pub struct PpsSourceActionIterator {
    iter: <Vec<PpsSourceAction> as IntoIterator>::IntoIter,
}

impl Default for PpsSourceActionIterator {
    fn default() -> Self {
        Self {
            iter: vec![].into_iter(),
        }
    }
}

impl Iterator for PpsSourceActionIterator {
    type Item = PpsSourceAction;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl PpsSourceActionIterator {
    fn from(data: Vec<PpsSourceAction>) -> Self {
        Self {
            iter: data.into_iter(),
        }
    }
}

macro_rules! actions {
    [$($action:expr),*] => {
        {
            PpsSourceActionIterator::from(vec![$($action),*])
        }
    }
}

impl PpsSource {
    #[instrument]
    pub fn new() -> (Self, PpsSourceActionIterator) {
        (
            Self {},
            actions!(PpsSourceAction::SetTimer(Duration::from_secs(0))),
        )
    }



    #[instrument(skip(self))]
        pub fn handle_incoming(
            &mut self,
            local_clock_time: NtpInstant,
            offset: NtpDuration,
            ntp_timestamp: NtpTimestamp,
            measurement_noise: f64,
        ) -> PpsSourceActionIterator {
            // generate a measurement
            let measurement = Measurement::from_pps(offset, local_clock_time, ntp_timestamp, measurement_noise);
           
            actions!(PpsSourceAction::UpdateSystem(PpsSourceUpdate {
                measurement: Some(measurement),
            }))
    }
}

