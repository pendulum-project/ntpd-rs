//! Implementation of [BasicFilter]

use fixed::traits::LossyInto;

use super::{Filter, FilterUpdate};
use crate::{port::Measurement, time::Duration, Clock};

#[derive(Debug)]
struct PrevStepData {
    measurement: Measurement,
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
}

impl Filter for BasicFilter {
    type Config = f64;

    fn new(gain: f64) -> Self {
        Self {
            last_step: None,
            offset_confidence: Duration::from_nanos(1_000_000_000),
            freq_confidence: 1e-4,
            gain,
        }
    }

    fn measurement<C: Clock>(&mut self, measurement: Measurement, clock: &mut C) -> FilterUpdate {
        // Reset on too-large difference
        if measurement.master_offset.abs() > Duration::from_nanos(1_000_000_000) {
            log::debug!("Offset too large, stepping {}", measurement.master_offset);
            self.offset_confidence = Duration::from_nanos(1_000_000_000);
            self.freq_confidence = 1e-4;

            if let Err(error) = clock.step_clock(-measurement.master_offset) {
                log::error!("Could not step clock: {:?}", error);
            }
            return Default::default();
        }

        // Determine offset
        let mut offset = measurement.master_offset;
        if offset.abs() > self.offset_confidence {
            offset = offset.clamp(-self.offset_confidence, self.offset_confidence);
            self.offset_confidence *= 2i32;
        } else {
            self.offset_confidence -= (self.offset_confidence - offset.abs()) * self.gain;
        }

        // And decide it's correction
        let correction = -offset * self.gain;

        let freq_corr = if let Some(last_step) = &self.last_step {
            // Calculate interval for us
            let interval_local: f64 =
                (measurement.event_time - last_step.measurement.event_time - last_step.correction)
                    .nanos()
                    .lossy_into();
            // and for the master
            let interval_master: f64 = ((measurement.event_time - measurement.master_offset)
                - (last_step.measurement.event_time - last_step.measurement.master_offset))
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

            // and decide the correction
            1.0 + (freq_diff - 1.0) * self.gain * 0.1
        } else {
            // No data, so no correction
            1.0
        };

        log::info!(
            "Offset to master: {:e}ns, corrected with phase change {:e}ns and freq change 1 + \
             {:e}x",
            measurement.master_offset.nanos(),
            correction.nanos(),
            freq_corr - 1.0
        );

        // Store data for next time
        self.last_step = Some(PrevStepData {
            measurement,
            correction,
        });

        if let Err(error) = clock.step_clock(correction) {
            log::error!("Could not step clock: {:?}", error);
        }
        if let Err(error) = clock.adjust_frequency(freq_corr) {
            log::error!("Could not adjust clock frequency: {:?}", error);
        }
        Default::default()
    }

    fn delay(&mut self, _delay: Duration) {
        // ignore
    }

    fn demobilize<C: Clock>(&mut self, _clock: &mut C) {
        // ignore
        Default::default()
    }

    fn update<C: Clock>(&mut self, _clock: &mut C) -> FilterUpdate {
        // ignore
        Default::default()
    }
}
