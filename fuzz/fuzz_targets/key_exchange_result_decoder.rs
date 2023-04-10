#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp_proto::fuzz_key_exchange_result_decoder;

fuzz_target!(|data: &[u8]| {
    fuzz_key_exchange_result_decoder(data);
});
