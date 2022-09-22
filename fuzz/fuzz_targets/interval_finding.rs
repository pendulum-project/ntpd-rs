#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp_proto::fuzz_find_interval;

fuzz_target!(|spec: Vec<(i64, u64)>| {
    fuzz_find_interval(&spec);
});
