#![no_main]

use libfuzzer_sys::fuzz_target;
use ptp_wire::Message;

fuzz_target!(|data: Vec<u8>| {
    // the default maximum size a fuzzed Vec<_> will be, as per
    //
    // > INFO: -max_len is not provided; libFuzzer will not generate inputs larger
    // than 4096 bytes
    let mut buf1 = [0u8; 4096];
    let mut buf2 = [0u8; 4096];

    assert!(data.len() <= buf1.len());

    if let Ok(a) = Message::deserialize(&data) {
        // verify that the tlv's are parsed without panics
        for tlv in a.suffix.tlvs() {
            let _ = tlv;
        }

        let written = a.serialize(&mut buf1).unwrap();
        assert!(data.len() >= written);

        let b = Message::deserialize(&data).unwrap();
        b.serialize(&mut buf2).unwrap();

        assert_eq!(buf1, buf2);
    }
});
