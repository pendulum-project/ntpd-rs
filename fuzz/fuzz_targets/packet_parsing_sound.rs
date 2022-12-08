#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp_proto::NtpPacket;
use pretty_assertions::assert_eq;

fuzz_target!(|data: Vec<u8>| {
    if let Ok(a) = NtpPacket::deserialize_without_decryption(&data) {
        let mut buf = vec![];
        a.serialize_without_encryption(&mut buf).unwrap();
        assert_eq!(data, buf);
    }
});
