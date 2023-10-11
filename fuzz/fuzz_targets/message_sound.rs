#![no_main]

use libfuzzer_sys::fuzz_target;
use statime::FuzzMessage;

fuzz_target!(|data: Vec<u8>| {
    // the default maximum size a fuzzed Vec<_> will be, as per
    //
    // > INFO: -max_len is not provided; libFuzzer will not generate inputs larger
    // than 4096 bytes
    let mut buf1 = [0u8; 4096];
    let mut buf2 = [0u8; 4096];

    assert!(data.len() <= buf1.len());

    if let Ok(a) = FuzzMessage::deserialize(&data) {
        // verify that the tlv's are parsed without panics
        for tlv in a.tlv() {
            let _ = tlv;
        }

        let written = a.serialize(&mut buf1).unwrap();
        assert!(data.len() >= written);

        let b = FuzzMessage::deserialize(&data).unwrap();
        b.serialize(&mut buf2).unwrap();

        assert_eq!(buf1, buf2);
    }
});
