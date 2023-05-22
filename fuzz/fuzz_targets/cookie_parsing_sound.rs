#![no_main]

use libfuzzer_sys::fuzz_target;
use ntp_proto::KeySetProvider;

fuzz_target!(|data: Vec<u8>| {
    let provider = KeySetProvider::new(1);

    let keyset = provider.get();

    if let Ok(decoded1) = keyset.decode_cookie_pub(&data) {
        let encoded1 = keyset.encode_cookie_pub(&decoded1);
        let decoded2 = keyset.decode_cookie_pub(&data).unwrap();
        let encoded2 = keyset.encode_cookie_pub(&decoded2);

        assert_eq!(encoded1, encoded2);
    }
});
