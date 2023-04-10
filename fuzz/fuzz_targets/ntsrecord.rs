#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp_proto::NtsRecord;

fuzz_target!(|data: &[u8]| {
    let mut decoder = NtsRecord::decoder();
    decoder.extend(data.iter().copied());

    // mimic test_decode_nts_time_nl_response() which has 11 steps
    let _ = decoder.step();
    let _ = decoder.step();
    let _ = decoder.step();
    let _ = decoder.step();
    let _ = decoder.step();
    let _ = decoder.step();
    let _ = decoder.step();
    let _ = decoder.step();
    let _ = decoder.step();
    let _ = decoder.step();
});
