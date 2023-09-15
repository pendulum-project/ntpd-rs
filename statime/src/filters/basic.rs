//! Implementation of [BasicFilter]

use fixed::traits::LossyInto;

use super::{Filter, FilterUpdate};
use crate::{port::Measurement, time::Duration, Clock, Time};

#[derive(Debug)]
struct PrevStepData {
    event_time: Time,
    offset: Duration,
    correction: Duration,
}

/// A simple averaging filter
///
/// This filter uses simple averaging to determine what the clock control
/// outputs should be.
#[derive(Debug)]
pub struct BasicFilter {
    last_step: Option<PrevStepData>,

    offset_confidence: Duration,
    freq_confidence: f64,

    gain: f64,

    cur_freq: f64,
}

impl Filter for BasicFilter {
    type Config = f64;

    fn new(gain: f64) -> Self {
        Self {
            last_step: None,
            offset_confidence: Duration::from_nanos(1_000_000_000),
            freq_confidence: 1e-4,
            gain,
            cur_freq: 0.0,
        }
    }

    fn measurement<C: Clock>(&mut self, measurement: Measurement, clock: &mut C) -> FilterUpdate {
        let mut update = FilterUpdate::default();

        if let Some(delay) = measurement.delay {
            update.mean_delay = Some(delay);
        }

        let Some(offset) = measurement.offset else {
            // No measurement, so no further actions
            return update;
        };

        // Reset on too-large difference
        if offset.abs() > Duration::from_nanos(1_000_000_000) {
            log::debug!("Offset too large, stepping {}", offset);
            self.offset_confidence = Duration::from_nanos(1_000_000_000);
            self.freq_confidence = 1e-4;

            if let Err(error) = clock.step_clock(-offset) {
                log::error!("Could not step clock: {:?}", error);
            }
            return update;
        }

        // Determine offset
        let mut clamped_offset = offset;
        if offset.abs() > self.offset_confidence {
            clamped_offset = offset.clamp(-self.offset_confidence, self.offset_confidence);
            self.offset_confidence *= 2i32;
        } else {
            self.offset_confidence -= (self.offset_confidence - offset.abs()) * self.gain;
        }

        // And decide it's correction
        let correction = -clamped_offset * self.gain;

        let freq_corr = if let Some(last_step) = &self.last_step {
            // Calculate interval for us
            let interval_local: f64 =
                (measurement.event_time - last_step.event_time - last_step.correction)
                    .nanos()
                    .lossy_into();
            // and for the master
            let interval_master: f64 = ((measurement.event_time - offset)
                - (last_step.event_time - last_step.offset))
                .nanos()
                .lossy_into();

            // get relative frequency difference
            let mut freq_diff = interval_local / interval_master;
            if libm::fabs(freq_diff - 1.0) > self.freq_confidence {
                freq_diff = freq_diff.clamp(1.0 - self.freq_confidence, 1.0 + self.freq_confidence);
                self.freq_confidence *= 2.0;
            } else {
                self.freq_confidence -=
                    (self.freq_confidence - libm::fabs(freq_diff - 1.0)) * self.gain;
            }

            // and decide the correction (and convert to ppm)
            -(freq_diff - 1.0) * self.gain * 0.1 * 1e6
        } else {
            // No data, so first run, so initialize
            if let Err(error) = clock.set_frequency(0.0) {
                log::error!("Could not initialize clock frequency: {:?}", error);
            }
            self.cur_freq = 0.0;
            0.0
        };

        // unwrap is ok here since we always have an offset
        log::info!(
            "Offset to master: {:e}ns, corrected with phase change {:e}ns and freq change {:e}ppm",
            offset.nanos(),
            correction.nanos(),
            freq_corr
        );

        // Store data for next time
        self.last_step = Some(PrevStepData {
            event_time: measurement.event_time,
            offset,
            correction,
        });

        if let Err(error) = clock.step_clock(correction) {
            log::error!("Could not step clock: {:?}", error);
        }
        if let Err(error) = clock.set_frequency(self.cur_freq + freq_corr) {
            log::error!("Could not adjust clock frequency: {:?}", error);
        } else {
            self.cur_freq += freq_corr;
        }
        update
    }

    fn demobilize<C: Clock>(self, _clock: &mut C) {
        // ignore
    }

    fn update<C: Clock>(&mut self, _clock: &mut C) -> FilterUpdate {
        // ignore
        Default::default()
    }
}
