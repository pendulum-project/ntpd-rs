use crate::time_types::{NtpInstant};
use crate::source::Measurement;
use crate::{NtpDuration, NtpTimestamp};
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
        timestamp: NtpTimestamp,
        measurement_noise: f64,
    ) -> GpsSourceActionIterator {
        
        // generate a measurement
        let measurement = Measurement::from_gps(
            offset,
            local_clock_time,
            timestamp,
            measurement_noise,
        );
       
        actions!(GpsSourceAction::UpdateSystem(GpsSourceUpdate {
            measurement: Some(measurement),
        }))
       
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gps_source_new() {
        let (gps_source, action_iter) = GpsSource::new();
        let actions: Vec<_> = action_iter.collect();
        assert_eq!(actions.len(), 1);
        if let GpsSourceAction::SetTimer(duration) = &actions[0] {
            assert_eq!(*duration, Duration::from_secs(0));
        } else {
            panic!("Expected SetTimer action");
        }
    }

    #[test]
    fn test_gps_source_handle_incoming() {
        let mut gps_source = GpsSource::new().0;
        let local_clock_time = NtpInstant::now();
        let offset = NtpDuration::from_seconds(0.0);
        let timestamp = NtpTimestamp::from_fixed_int(0);
        let measurement_noise = 0.0;

        let action_iter = gps_source.handle_incoming(
            local_clock_time,
            offset,
            timestamp,
            measurement_noise,
        );
        let actions: Vec<_> = action_iter.collect();
        assert_eq!(actions.len(), 1);
        if let GpsSourceAction::UpdateSystem(update) = &actions[0] {
            assert!(update.measurement.is_some());
        } else {
            panic!("Expected UpdateSystem action");
        }
    }

    #[test]
    fn test_gps_source_action_set_timer() {
        let duration = Duration::from_secs(10);
        let action = GpsSourceAction::SetTimer(duration);
        if let GpsSourceAction::SetTimer(d) = action {
            assert_eq!(d, duration);
        } else {
            panic!("Expected SetTimer action");
        }
    }

    #[test]
    fn test_gps_source_action_reset() {
        let action = GpsSourceAction::Reset;
        match action {
            GpsSourceAction::Reset => (),
            _ => panic!("Expected Reset action"),
        }
    }

    #[test]
    fn test_gps_source_action_demobilize() {
        let action = GpsSourceAction::Demobilize;
        match action {
            GpsSourceAction::Demobilize => (),
            _ => panic!("Expected Demobilize action"),
        }
    }

    #[test]
    fn test_gps_source_action_send() {
        let action = GpsSourceAction::Send();
        match action {
            GpsSourceAction::Send() => (),
            _ => panic!("Expected Send action"),
        }
    }

    #[test]
    fn test_gps_source_default_action_iterator() {
        let action_iter = GpsSourceActionIterator::default();
        assert_eq!(action_iter.count(), 0);
    }
}