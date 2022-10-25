#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp_proto::NtpPacket;

fuzz_target!(|data: Vec<u8>| {
    if let Ok(a) = NtpPacket::deserialize(&data) {
        let mut buf = vec![];
        a.serialize(&mut buf).unwrap();
        assert_eq!(data, buf);
    }
});
