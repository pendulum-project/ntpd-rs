use super::{Clock, Watch};
use crate::{clock::TimeProperties, datastructures::common::ClockQuality, time::OffsetTime};
use ringbuffer::{RingBuffer, RingBufferExt, RingBufferWrite};
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
    offset_buffer: ringbuffer::ConstGenericRingBuffer<OffsetTime, 32>,
    frequency_buffer: ringbuffer::ConstGenericRingBuffer<f64, 32>,
    alarm_sender: mpsc::Sender<(<<Self as Clock>::W as Watch>::WatchId, OffsetTime)>,
}

impl LinuxClock {
    pub fn new(clock: RawLinuxClock) -> (Self, AlarmReceiver) {
        let (alarm_sender, alarm_receiver) = mpsc::channel();

        (
            Self {
                clock: clock.clone(),
                next_watch_id: 0,
                offset_buffer: Default::default(),
                frequency_buffer: Default::default(),
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

    fn now(&self) -> OffsetTime {
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
        time_offset: OffsetTime,
        frequency_multiplier: f64,
        time_properties: TimeProperties,
    ) -> Result<bool, Self::E> {
        self.offset_buffer.push(time_offset);
        self.frequency_buffer.push(frequency_multiplier);

        let average_offset =
            self.offset_buffer.iter().sum::<OffsetTime>() / self.offset_buffer.len() as i128;
        let average_frequency_multiplier =
            self.frequency_buffer.iter().sum::<f64>() / self.offset_buffer.len() as f64;

        if let TimeProperties::PtpTime {
            leap_61, leap_59, ..
        } = time_properties
        {
            self.clock
                .set_leap_seconds(leap_61, leap_59)
                .map_err(Error::LinuxError)?;
        }

        let adjust_result = self.clock.adjust_clock(
            (average_offset * 1_000_000_000).to_num::<f64>(),
            average_frequency_multiplier,
        );

        match adjust_result {
            Ok(_) => Ok(average_offset < 1000),
            Err(e) => Err(Error::LinuxError(e)),
        }
    }
}

pub struct LinuxWatch {
    clock: RawLinuxClock,
    id: u32,
    alarm_sender: mpsc::Sender<(<Self as Watch>::WatchId, OffsetTime)>,
}

impl Watch for LinuxWatch {
    type WatchId = u32;

    fn now(&self) -> OffsetTime {
        self.clock.get_clock_state().unwrap().0.get_time()
    }

    fn set_alarm(&mut self, from_now: OffsetTime) {
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
    alarm_receiver: mpsc::Receiver<(u32, OffsetTime)>,
    alarms: HashMap<u32, OffsetTime>,
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

    fn earliest_alarm(&mut self) -> Option<(u32, OffsetTime)> {
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

    pub fn interval_to_next_alarm(&mut self) -> Option<OffsetTime> {
        match self.earliest_alarm() {
            Some((_, alarm_time)) => {
                let cur_time = self.clock.get_clock_state().unwrap().0.get_time();
                if cur_time > alarm_time {
                    Some(0.into())
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
    use std::time::Duration;

    #[test]
    fn linux_clock_alarm() {
        // This test does do some time dependent things, so it is imaginable that it can spuriously fail

        let (mut clock, mut alarm_receiver) = LinuxClock::new(RawLinuxClock::get_realtime_clock());

        let mut watch_1 = clock.get_watch();
        let mut watch_2 = clock.get_watch();

        assert_eq!(alarm_receiver.alarms.len(), 0);

        watch_1.set_alarm(2_000_000.into());
        assert_eq!(alarm_receiver.check(), None);
        assert_eq!(alarm_receiver.alarms.len(), 1);

        watch_2.set_alarm(2_000_000.into());
        assert_eq!(alarm_receiver.check(), None);
        assert_eq!(alarm_receiver.alarms.len(), 2);

        watch_1.set_alarm(4_000_000.into());
        assert_eq!(alarm_receiver.check(), None);
        assert_eq!(alarm_receiver.alarms.len(), 2);

        std::thread::sleep(Duration::from_millis(10));

        assert_eq!(alarm_receiver.check(), Some(watch_2.id()));
        assert_eq!(alarm_receiver.check(), Some(watch_1.id()));
    }
}
