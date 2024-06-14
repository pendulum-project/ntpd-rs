use crate::time_types::{ NtpInstant};
use crate::source::Measurement;
use crate::NtpDuration;
use std::time::Duration;

use tracing::{instrument, warn};

#[derive(Debug)]
pub struct GpsSource {

}

#[derive(Debug, Copy, Clone)]
pub struct GpsSourceUpdate {
    pub(crate) measurement: Option<Measurement>,
}

#[cfg(feature = "__internal-test")]
impl GpsSourceUpdate {
    pub fn measurement(measurement: Measurement) -> Self {
        GpsSourceUpdate {
            measurement: Some(measurement),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum GpsSourceAction {
    /// Send a message over the network. When this is issued, the network port maybe changed.
    Send(),
    /// Send an update to [`System`](crate::system::System)
    UpdateSystem(GpsSourceUpdate),
    /// Call [`NtpSource::handle_timer`] after given duration
    SetTimer(Duration),
    /// A complete reset of the connection is necessary, including a potential new NTSKE client session and/or DNS lookup.
    Reset,
    /// We must stop talking to this particular server.
    Demobilize,
}

#[derive(Debug)]
pub struct GpsSourceActionIterator {
    iter: <Vec<GpsSourceAction> as IntoIterator>::IntoIter,
}

impl Default for GpsSourceActionIterator {
    fn default() -> Self {
        Self {
            iter: vec![].into_iter(),
        }
    }
}

impl Iterator for GpsSourceActionIterator {
    type Item = GpsSourceAction;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl GpsSourceActionIterator {
    fn from(data: Vec<GpsSourceAction>) -> Self {
        Self {
            iter: data.into_iter(),
        }
    }
}

macro_rules! actions {
    [$($action:expr),*] => {
        {
            GpsSourceActionIterator::from(vec![$($action),*])
        }
    }
}

impl GpsSource {
    #[instrument]
    pub fn new(
    ) -> (Self, GpsSourceActionIterator) {
        (
            Self {
            },
            actions!(GpsSourceAction::SetTimer(Duration::from_secs(0))),
        )
    }

    #[instrument(skip(self))]
    pub fn handle_incoming(
        &mut self,
        local_clock_time: NtpInstant,
        offset: NtpDuration,
    ) -> GpsSourceActionIterator {
        
        // generate a measurement
        let measurement = Measurement::from_gps(
            offset,
            local_clock_time,
        );
       
        actions!(GpsSourceAction::UpdateSystem(GpsSourceUpdate {
            measurement: Some(measurement),
        }))
       
    }
}