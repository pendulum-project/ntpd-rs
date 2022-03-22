//! Implementation of the abstract clock for the linux platform

use super::{Clock, Watch};
use crate::{
    clock::TimeProperties,
    datastructures::common::ClockQuality,
    time::{Duration, Instant},
};
use fixed::traits::LossyInto;
use std::{collections::HashMap, sync::mpsc};

mod raw;
mod timex;

pub use raw::RawLinuxClock;

#[derive(Debug, Clone)]
pub enum Error {
    LinuxError(i32),
}

pub struct LinuxClock {
    clock: RawLinuxClock,
    next_watch_id: u32,
    alarm_sender: mpsc::Sender<(<<Self as Clock>::W as Watch>::WatchId, Instant)>,
}

impl LinuxClock {
    pub fn new(clock: RawLinuxClock) -> (Self, AlarmReceiver) {
        let (alarm_sender, alarm_receiver) = mpsc::channel();

        (
            Self {
                clock: clock.clone(),
                next_watch_id: 0,
                alarm_sender,
            },
            AlarmReceiver {
                alarm_receiver,
                clock,
                alarms: HashMap::new(),
            },
        )
    }
}

impl Clock for LinuxClock {
    type E = Error;
    type W = LinuxWatch;

    fn now(&self) -> Instant {
        self.clock.get_clock_state().unwrap().0.get_time()
    }

    fn quality(&self) -> ClockQuality {
        self.clock.quality()
    }

    fn get_watch(&mut self) -> Self::W {
        let watch_id = self.next_watch_id;
        self.next_watch_id += 1;

        LinuxWatch {
            clock: self.clock.clone(),
            id: watch_id,
            alarm_sender: self.alarm_sender.clone(),
        }
    }

    fn adjust(
        &mut self,
        time_offset: Duration,
        frequency_multiplier: f64,
        time_properties: TimeProperties,
    ) -> Result<bool, Self::E> {
        if let TimeProperties::PtpTime {
            leap_61, leap_59, ..
        } = time_properties
        {
            self.clock
                .set_leap_seconds(leap_61, leap_59)
                .map_err(Error::LinuxError)?;
        }

        let time_offset_float: f64 = time_offset.nanos().lossy_into();
        let adjust_result = self
            .clock
            .adjust_clock(time_offset_float / 1e9, frequency_multiplier);

        match adjust_result {
            Ok(_) => Ok(true),
            Err(e) => Err(Error::LinuxError(e)),
        }
    }
}

pub struct LinuxWatch {
    clock: RawLinuxClock,
    id: u32,
    alarm_sender: mpsc::Sender<(<Self as Watch>::WatchId, Instant)>,
}

impl Watch for LinuxWatch {
    type WatchId = u32;

    fn now(&self) -> Instant {
        self.clock.get_clock_state().unwrap().0.get_time()
    }

    fn set_alarm(&mut self, from_now: Duration) {
        let alarm_time = self.now() + from_now;
        // Send the alarm time to the alarm receiver
        self.alarm_sender.send((self.id, alarm_time)).unwrap();
    }

    fn id(&self) -> Self::WatchId {
        self.id
    }
}

/// Object that receives all set alarms of all watches
pub struct AlarmReceiver {
    clock: RawLinuxClock,
    alarm_receiver: mpsc::Receiver<(u32, Instant)>,
    alarms: HashMap<u32, Instant>,
}

impl AlarmReceiver {
    /// Checks if an alarm went off
    pub fn check(&mut self) -> Option<u32> {
        // Check if we have an alarm and if it would go off
        match self.earliest_alarm() {
            Some((alarm_id, alarm_time))
                if alarm_time < self.clock.get_clock_state().unwrap().0.get_time() =>
            {
                let alarm_id = alarm_id;
                self.alarms.remove(&alarm_id);
                Some(alarm_id)
            }
            _ => None,
        }
    }

    fn earliest_alarm(&mut self) -> Option<(u32, Instant)> {
        // Gather all alarms into the hashmap
        while let Ok((clock_id, alarm_time)) = self.alarm_receiver.try_recv() {
            self.alarms.insert(clock_id, alarm_time);
        }

        // Get which one will go off the earliest
        let earliest_alarm = self
            .alarms
            .iter()
            .reduce(|l, r| if l.1 <= r.1 { l } else { r });
        earliest_alarm.map(|(a, b)| (a.to_owned(), b.to_owned()))
    }

    pub fn interval_to_next_alarm(&mut self) -> Option<Duration> {
        match self.earliest_alarm() {
            Some((_, alarm_time)) => {
                let cur_time = self.clock.get_clock_state().unwrap().0.get_time();
                if cur_time > alarm_time {
                    Some(Duration::default())
                } else {
                    Some(alarm_time - cur_time)
                }
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_clock_alarm() {
        // This test does do some time dependent things, so it is imaginable that it can spuriously fail

        let (mut clock, mut alarm_receiver) = LinuxClock::new(RawLinuxClock::get_realtime_clock());

        let mut watch_1 = clock.get_watch();
        let mut watch_2 = clock.get_watch();

        assert_eq!(alarm_receiver.alarms.len(), 0);

        watch_1.set_alarm(Duration::from_nanos(2_000_000));
        assert_eq!(alarm_receiver.check(), None);
        assert_eq!(alarm_receiver.alarms.len(), 1);

        watch_2.set_alarm(Duration::from_nanos(2_000_000));
        assert_eq!(alarm_receiver.check(), None);
        assert_eq!(alarm_receiver.alarms.len(), 2);

        watch_1.set_alarm(Duration::from_nanos(4_000_000));
        assert_eq!(alarm_receiver.check(), None);
        assert_eq!(alarm_receiver.alarms.len(), 2);

        std::thread::sleep(std::time::Duration::from_millis(10));

        assert_eq!(alarm_receiver.check(), Some(watch_2.id()));
        assert_eq!(alarm_receiver.check(), Some(watch_1.id()));
    }
}
