#![no_main]
use libfuzzer_sys::fuzz_target;
use statime_ntp::fuzz_duration_from_seconds;

fuzz_target!(|v: f64| {
    fuzz_duration_from_seconds(v);
});
