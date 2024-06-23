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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pps_source_new() {
        let (pps_source, action_iter) = PpsSource::new();
        let actions: Vec<_> = action_iter.collect();
        assert_eq!(actions.len(), 1);
        if let PpsSourceAction::SetTimer(duration) = &actions[0] {
            assert_eq!(*duration, Duration::from_secs(0));
        } else {
            panic!("Expected SetTimer action");
        }
    }

    #[test]
    fn test_pps_source_handle_incoming() {
        let mut pps_source = PpsSource::new().0;
        let local_clock_time = NtpInstant::now();
        let offset = NtpDuration::from_seconds(0.0);
        let ntp_timestamp = NtpTimestamp::from_fixed_int(0);
        let measurement_noise = 0.0;

        let action_iter = pps_source.handle_incoming(
            local_clock_time,
            offset,
            ntp_timestamp,
            measurement_noise,
        );
        let actions: Vec<_> = action_iter.collect();
        assert_eq!(actions.len(), 1);
        if let PpsSourceAction::UpdateSystem(update) = &actions[0] {
            assert!(update.measurement.is_some());
        } else {
            panic!("Expected UpdateSystem action");
        }
    }

    #[test]
    fn test_pps_source_action_set_timer() {
        let duration = Duration::from_secs(10);
        let action = PpsSourceAction::SetTimer(duration);
        if let PpsSourceAction::SetTimer(d) = action {
            assert_eq!(d, duration);
        } else {
            panic!("Expected SetTimer action");
        }
    }

    #[test]
    fn test_pps_source_action_reset() {
        let action = PpsSourceAction::Reset;
        match action {
            PpsSourceAction::Reset => (),
            _ => panic!("Expected Reset action"),
        }
    }

    #[test]
    fn test_pps_source_action_demobilize() {
        let action = PpsSourceAction::Demobilize;
        match action {
            PpsSourceAction::Demobilize => (),
            _ => panic!("Expected Demobilize action"),
        }
    }

    #[test]
    fn test_pps_source_action_send() {
        let action = PpsSourceAction::Send();
        match action {
            PpsSourceAction::Send() => (),
            _ => panic!("Expected Send action"),
        }
    }

    #[test]
    fn test_pps_source_default_action_iterator() {
        let action_iter = PpsSourceActionIterator::default();
        assert_eq!(action_iter.count(), 0);
    }
}