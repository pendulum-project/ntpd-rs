#![no_main]
#![expect(clippy::type_complexity)]

use std::{
    borrow::Cow,
    io::{Cursor, Write},
    net::IpAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use libfuzzer_sys::fuzz_target;
use ntp_proto::{
    test_cookie, v5::BloomFilter, EncryptResult, ExtensionField, ExtensionHeaderVersion,
    FilterAction, FilterList, HandleInnerData, KeySetProvider, NtpServerInfo, NtpSnapshot,
    NtpVersion, ReferenceId, Server, ServerConfig, ServerReason, ServerResponse, ServerStatHandler,
};
use rand::{rngs::StdRng, set_thread_rng, SeedableRng};
use statime_base::{Clock, TimeSnapshot, Timestamp, TAI};

const fn next_multiple_of(lhs: u16, rhs: u16) -> u16 {
    match lhs % rhs {
        0 => lhs,
        r => lhs + (rhs - r),
    }
}

fuzz_target!(|parts: (
    Vec<u8>,
    u64,
    [u8; 4],
    Option<(Vec<u8>, Vec<u8>, Vec<u8>, ExtensionHeaderVersion)>
)| {
    set_thread_rng(StdRng::seed_from_u64(parts.1));

    // Can't test reencoding because of the keyset
    let provider = KeySetProvider::dangerous_new_deterministic(1);

    let keyset = provider.get();

    let mut cursor = Cursor::new([0u8; 8192]);

    let message = if let Some(encrypted) = parts.3 {
        // Build packet
        let _ = cursor.write_all(&parts.0);
        let cookie = test_cookie();
        let enc_cookie = keyset.encode_cookie_pub(&cookie);
        let _ = ExtensionField::NtsCookie(Cow::Borrowed(&enc_cookie)).serialize_pub(
            &mut cursor,
            4,
            encrypted.3,
        );
        let _ = cursor.write_all(&encrypted.0);

        let mut ciphertext = encrypted.1.clone();
        ciphertext.resize(ciphertext.len() + 32, 0);
        let EncryptResult {
            nonce_length,
            ciphertext_length,
        } = cookie
            .c2s
            .encrypt(
                &mut ciphertext,
                encrypted.1.len(),
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
        let _ = cursor.write_all(&encrypted.2);
        cursor.get_ref()
    } else {
        let _ = cursor.write_all(&parts.0);
        cursor.get_ref()
    };

    let denylist = FilterList {
        filter: vec!["1.0.0.0/24".parse().unwrap()],
        action: FilterAction::Ignore,
    };

    let allowlist = FilterList {
        filter: vec!["1.0.0.0/8".parse().unwrap()],
        action: FilterAction::Deny,
    };

    let ip = IpAddr::from(parts.2);

    let mut server = Server::new_internal(
        ServerConfig {
            denylist,
            allowlist,
            rate_limiting_cache_size: 0,
            rate_limiting_cutoff: Duration::from_secs(1),
            require_nts: None,
            accepted_versions: vec![NtpVersion::V3, NtpVersion::V4, NtpVersion::V5],
        },
        TestClock {
            cur: Timestamp::from_seconds_nanos_since_unix_epoch(100, 0),
        },
        Arc::new(RwLock::new(NtpServerInfo {
            ntp_snapshot: NtpSnapshot {
                stratum: 1,
                reference_id: ReferenceId::NONE,
                bloom_filter: BloomFilter::new(),
            },
            time_snapshot: TimeSnapshot {
                precision: statime_base::Duration::from_f64_seconds(0.00001),
                root_delay: statime_base::Duration::from_f64_seconds(0.01),
                root_variance_base_time: statime_base::Timestamp::UNIX_EPOCH
                    + statime_base::Duration::from_seconds_nanos(90, 0),
                root_variance_base: 1e-9,
                root_variance_linear: 0.0,
                root_variance_quadratic: 0.0,
                root_variance_cubic: 0.0,
                leap_indicator: Some(statime_base::LeapStatus::None),
                accumulated_steps: statime_base::Duration::from_f64_seconds(0.0),
                accumulated_steps_threshold: None,
            },
        })),
        keyset,
    );

    let mut buffer = [0u8; 8192];

    if let Ok(HandleInnerData {
        packet,
        cipher,
        desired_size,
        ..
    }) = server.fuzz_handle_inner(
        ip,
        Timestamp::from_seconds_nanos_since_unix_epoch(99, 900000000),
        message,
        &mut TestStatHandler,
    ) {
        let mut cursor = Cursor::new(&mut buffer[..message.len()]);
        assert!(packet
            .serialize(&mut cursor, &cipher.as_deref(), desired_size)
            .is_ok());
    }
});

#[derive(Debug, Clone)]
struct TestClock {
    cur: Timestamp<TAI>,
}

impl Clock<TAI> for TestClock {
    fn now(&self) -> Result<Timestamp<TAI>, statime_base::ClockError> {
        Ok(self.cur)
    }

    fn set_frequency(&self, _freq: f64) -> Result<Timestamp<TAI>, statime_base::ClockError> {
        unimplemented!()
    }

    fn get_frequency(&self) -> Result<f64, statime_base::ClockError> {
        Ok(0.0)
    }

    fn max_frequency(&self) -> Result<f64, statime_base::ClockError> {
        Ok(500e-6)
    }

    fn step_clock(
        &self,
        _offset: statime_base::Duration,
    ) -> Result<Timestamp<TAI>, statime_base::ClockError> {
        unimplemented!()
    }

    fn error_estimate_update(
        &self,
        _est_error: statime_base::Duration,
        _max_error: statime_base::Duration,
    ) -> Result<(), statime_base::ClockError> {
        unimplemented!()
    }

    fn leap_update(
        &self,
        _leap_status: statime_base::LeapStatus,
    ) -> Result<(), statime_base::ClockError> {
        unimplemented!()
    }

    fn synchronization_update(&self, _synchronized: bool) -> Result<(), statime_base::ClockError> {
        unimplemented!()
    }
}

#[derive(Debug, Default)]
struct TestStatHandler;

impl ServerStatHandler for TestStatHandler {
    fn register(
        &mut self,
        _version: u8,
        _nts: bool,
        _reason: ServerReason,
        _response: ServerResponse,
    ) {
    }
}
