#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp_proto::NtpHeader;

fuzz_target!(|data: [u8;48]| {
    match NtpHeader::deserialize(&data) {
        Ok(a) => {
            let b = a.serialize();
            assert_eq!(data, b);
        },
        Err(_) => {},
    }
});
