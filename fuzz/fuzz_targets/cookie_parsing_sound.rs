#![no_main]

use libfuzzer_sys::fuzz_target;
use statime_ntp::KeySetProvider;

fuzz_target!(|data: Vec<u8>| {
    let provider = KeySetProvider::dangerous_new_deterministic(1);

    let keyset = provider.get();

    let _ = keyset.decode_cookie_pub(&data);
});
