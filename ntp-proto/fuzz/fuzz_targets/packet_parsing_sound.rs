#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp_proto::NtpHeader;

fuzz_target!(|data: [u8;48]| {
    let a = NtpHeader::deserialize(&data);
    let b = a.serialize();
    assert_eq!(data, b);
});
