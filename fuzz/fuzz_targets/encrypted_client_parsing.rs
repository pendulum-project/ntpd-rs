#![no_main]

use std::io::{Cursor, Write};

use libfuzzer_sys::fuzz_target;
use ntp_proto::{test_cookie, EncryptResult, NtpPacket};
use rand::{rngs::StdRng, set_thread_rng, SeedableRng};

const fn next_multiple_of(lhs: u16, rhs: u16) -> u16 {
    match lhs % rhs {
        0 => lhs,
        r => lhs + (rhs - r),
    }
}

fuzz_target!(|parts: (u64, Vec<u8>, Vec<u8>, Vec<u8>)| {
    set_thread_rng(StdRng::seed_from_u64(parts.0));

    // Build packet
    let mut cursor = Cursor::new([0u8; 8192]);
    let _ = cursor.write_all(&parts.1);
    let cookie = test_cookie();

    let mut ciphertext = parts.2.clone();
    ciphertext.resize(ciphertext.len() + 32, 0);
    let EncryptResult {
        nonce_length,
        ciphertext_length,
    } = cookie
        .c2s
        .encrypt(
            &mut ciphertext,
            parts.2.len(),
            &cursor.get_ref()[..cursor.position() as usize],
        )
        .unwrap();

    let _ = cursor.write_all(&0x404u16.to_be_bytes());
    let _ = cursor.write_all(
        &(8 + next_multiple_of((nonce_length + ciphertext_length) as u16, 4)).to_be_bytes(),
    );
    let _ = cursor.write_all(&(nonce_length as u16).to_be_bytes());
    let _ = cursor.write_all(&(ciphertext_length as u16).to_be_bytes());
    let _ = cursor.write_all(&ciphertext);
    let _ = cursor.write_all(&parts.3);

    let _ = NtpPacket::deserialize(cursor.get_ref(), &Some(cookie.s2c.as_ref()));
});
