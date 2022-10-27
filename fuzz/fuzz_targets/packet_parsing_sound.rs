#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp_proto::NtpPacket;

fuzz_target!(|data: [u8; 48]| {
    if let Ok(a) = NtpPacket::deserialize(&data) {
        let b = a.serialize();
        assert_eq!(data, b);
    }
});
