use std::ops::{Deref, DerefMut};

use bitflags::bitflags;
use libc::timex;
use statime::{Duration, Instant};

use crate::clock::raw::Fixed;

#[derive(Clone)]
pub struct Timex(timex);

#[allow(dead_code)]
impl Timex {
    pub fn new() -> Self {
        Self(new_timex())
    }

    pub fn get_status(&self) -> StatusFlags {
        StatusFlags::from_bits_truncate(self.status)
    }

    pub fn set_status(&mut self, value: StatusFlags) {
        self.status = value.bits();
    }

    pub fn get_mode(&self) -> AdjustFlags {
        AdjustFlags::from_bits_truncate(self.modes)
    }

    pub fn set_mode(&mut self, value: AdjustFlags) {
        self.modes = value.bits();
    }

    /// The frequency offset in PPM
    pub fn get_frequency(&self) -> Fixed {
        Fixed::from_bits(self.freq)
    }

    /// The frequency offset in PPM
    pub fn set_frequency(&mut self, value: Fixed) {
        self.freq = value.to_bits().clamp(-32768000, 32768000);
    }

    /// The pps frequency offset in PPM
    pub fn get_pps_frequency(&self) -> Fixed {
        Fixed::from_bits(self.ppsfreq)
    }

    /// The stabil frequency offset in PPM
    pub fn get_stabil_frequency(&self) -> Fixed {
        Fixed::from_bits(self.stabil)
    }

    pub fn get_time(&self) -> Instant {
        let time = self.time;
        let nanos = self.get_status().contains(StatusFlags::NANO);

        let secs = Instant::from_secs(time.tv_sec.unsigned_abs() as _);
        let sub_secs = if nanos {
            Duration::from_nanos(time.tv_usec as _)
        } else {
            Duration::from_micros(time.tv_usec as _)
        };

        secs + sub_secs
    }
}

impl Deref for Timex {
    type Target = timex;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Timex {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// https://manpages.debian.org/testing/manpages-dev/ntp_adjtime.3.en.html#DESCRIPTION
bitflags! {
    pub struct StatusFlags: i32 {
        /// Enable phase-locked loop (PLL) updates via ADJ_OFFSET.
        const PLL = libc::STA_PLL;
        /// Enable PPS (pulse-per-second) frequency discipline.
        const PPSFREQ = libc::STA_PPSFREQ;
        /// Enable PPS time discipline.
        const PPSTIME = libc::STA_PPSTIME;
        /// Select frequency-locked loop (FLL) mode.
        const FLL = libc::STA_FLL;
        /// Insert a leap second after the last second of the UTC day, thus extending the last minute of the day by one second.
        /// Leap-second insertion will occur each day, so long as this flag remains set.
        const INS = libc::STA_INS;
        /// Delete a leap second at the last second of the UTC day.
        /// Leap second deletion will occur each day, so long as this flag remains set.
        const DEL = libc::STA_DEL;
        /// Clock unsynchronized.
        const UNSYNC = libc::STA_UNSYNC;
        /// Hold frequency. Normally adjustments made via ADJ_OFFSET result in dampened frequency adjustments also being made.
        /// So a single call corrects the current offset, but as offsets in the same direction are made repeatedly, the small frequency adjustments will accumulate to fix the long-term skew.
        ///
        /// This flag prevents the small frequency adjustment from being made when correcting for an ADJ_OFFSET value.
        const FREQHOLD = libc::STA_FREQHOLD;
        /// A valid PPS (pulse-per-second) signal is present.
        const PPSSIGNAL = libc::STA_PPSSIGNAL;
        /// PPS signal jitter exceeded.
        const PPSJITTER = libc::STA_PPSJITTER;
        /// PPS signal wander exceeded.
        const PPSWANDER = libc::STA_PPSWANDER;
        /// PPS signal calibration error.
        const PPSERROR = libc::STA_PPSERROR;
        /// Clock hardware fault.
        const CLOCKERR = libc::STA_CLOCKERR;
        /// Resolution (0 = microsecond, 1 = nanoseconds). Set via ADJ_NANO, cleared via ADJ_MICRO.
        const NANO = libc::STA_NANO;
        /// Mode (0 = Phase Locked Loop, 1 = Frequency Locked Loop).
        const MODE = libc::STA_MODE;
        /// Clock source (0 = A, 1 = B); currently unused.
        const CLK = libc::STA_CLK;
    }

    pub struct AdjustFlags: u32 {
        /// Set time offset from buf.offset. Since Linux 2.6.26, the supplied value is clamped to the range (-0.5s, +0.5s).
        /// In older kernels, an EINVAL error occurs if the supplied value is out of range.
        const OFFSET = libc::ADJ_OFFSET;
        /// Set frequency offset from buf.freq. Since Linux 2.6.26, the supplied value is clamped to the range (-32768000, +32768000).
        /// In older kernels, an EINVAL error occurs if the supplied value is out of range.
        const FREQUENCY = libc::ADJ_FREQUENCY;
        /// Set maximum time error from buf.maxerror.
        const MAXERROR = libc::ADJ_MAXERROR;
        /// Set estimated time error from buf.esterror.
        const ESTERROR = libc::ADJ_ESTERROR;
        /// Set clock status bits from buf.status.
        const STATUS = libc::ADJ_STATUS;
        /// Set PLL time constant from buf.constant. If the STA_NANO status flag is clear, the kernel adds 4 to this value.
        const TIMECONST = libc::ADJ_TIMECONST;
        /// Add buf.time to the current time. If buf.status includes the ADJ_NANO flag, then buf.time.tv_usec is interpreted as a nanosecond value;
        /// otherwise it is interpreted as microseconds.
        ///
        /// The value of buf.time is the sum of its two fields, but the field buf.time.tv_usec must always be nonnegative.
        /// The following example shows how to normalize a timeval with nanosecond resolution.
        ///
        /// ```C
        /// while (buf.time.tv_usec < 0) {
        ///     buf.time.tv_sec  -= 1;
        ///     buf.time.tv_usec += 1000000000;
        /// }
        /// ```
        const SETOFFSET = libc::ADJ_SETOFFSET;
        /// Select microsecond resolution.
        const MICRO = libc::ADJ_MICRO;
        /// Select nanosecond resolution. Only one of ADJ_MICRO and ADJ_NANO should be specified.
        const NANO = libc::ADJ_NANO;
        /// Set TAI (Atomic International Time) offset from buf.constant.
        ///
        /// ADJ_TAI should not be used in conjunction with ADJ_TIMECONST, since the latter mode also employs the buf.constant field.
        /// For a complete explanation of TAI and the difference between TAI and UTC, see [BIPM](http://www.bipm.org/en/bipm/tai/tai.html)
        const TAI = libc::ADJ_TAI;
        /// Set tick value from buf.tick.
        const TICK = libc::ADJ_TICK;
        /// Old-fashioned adjtime(3): (gradually) adjust time by value specified in buf.offset, which specifies an adjustment in microseconds.
        const OFFSET_SINGLESHOT = libc::ADJ_OFFSET_SINGLESHOT;
        /// Return (in buf.offset) the remaining amount of time to be adjusted after an earlier ADJ_OFFSET_SINGLESHOT operation.
        /// This feature was added in Linux 2.6.24, but did not work correctly until Linux 2.6.28.
        const OFFSET_SS_READ = libc::ADJ_OFFSET_SS_READ;
    }
}
fn new_timex() -> timex {
    timex {
        modes: 0,
        offset: 0,
        freq: 0,
        maxerror: 0,
        esterror: 0,
        status: 0,
        constant: 0,
        precision: 0,
        tolerance: 0,
        time: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        tick: 0,
        ppsfreq: 0,
        jitter: 0,
        shift: 0,
        stabil: 0,
        jitcnt: 0,
        calcnt: 0,
        errcnt: 0,
        stbcnt: 0,
        tai: 0,
        __unused1: 0,
        __unused2: 0,
        __unused3: 0,
        __unused4: 0,
        __unused5: 0,
        __unused6: 0,
        __unused7: 0,
        __unused8: 0,
        __unused9: 0,
        __unused10: 0,
        __unused11: 0,
    }
}
