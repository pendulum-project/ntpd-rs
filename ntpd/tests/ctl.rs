use std::{
    io::Write,
    os::unix::net::UnixListener,
    process::{Command, Output},
    thread::spawn,
};

fn contains_bytes(mut haystack: &[u8], needle: &[u8]) -> bool {
    while haystack.len() >= needle.len() {
        if haystack.starts_with(needle) {
            return true;
        }
        haystack = &haystack[1..];
    }
    false
}

fn test_ntp_ctl_output(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ntp-ctl"))
        .args(args)
        .output()
        .unwrap()
}

const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");
const CARGO_TARGET_TMPDIR: &str = env!("CARGO_TARGET_TMPDIR");

#[test]
fn test_validate_bad() {
    let result = test_ntp_ctl_output(&[
        "validate",
        "-c",
        &format!("{CARGO_MANIFEST_DIR}/testdata/config/invalid.toml",),
    ]);

    assert!(contains_bytes(
        &result.stderr,
        b"unknown field `does-not-exist`"
    ));
    assert_eq!(result.status.code(), Some(1));
}

#[test]
fn test_validate_good() {
    let result = test_ntp_ctl_output(&[
        "validate",
        "-c",
        &format!("{CARGO_MANIFEST_DIR}/../ntp.toml"),
    ]);

    assert!(contains_bytes(&result.stderr, b"good"));
    assert_eq!(result.status.code(), Some(0));
}

const EXAMPLE_SOCKET_OUTPUT: &str = r#"{"program":{"version":"1.1.2","build_commit":"75fcca08b7db512585d62cf0d1d04289e2ff3518","build_commit_date":"2024-05-24","uptime_seconds":183.351648574},"system":{"stratum":3,"reference_id":3000493080,"accumulated_steps_threshold":null,"precision":3.814697266513178e-6,"root_delay":0.013193579859378184,"root_dispersion":0.0004211952910807904,"leap_indicator":"NoWarning","accumulated_steps":0.0},"sources":[{"offset":0.000557237770538134,"uncertainty":0.0002179115545511971,"delay":0.01588847721365478,"remote_delay":0.002716064453757383,"remote_uncertainty":0.0012512207034163225,"last_update":{"timestamp":16860021293684455212},"unanswered_polls":0,"poll_interval":4, "nts_cookies": 0,"name":"ntpd-rs.pool.ntp.org:123","address":"154.51.12.220:123","id":2},{"offset":-0.0003063457553056874,"uncertainty":0.00023756013257372196,"delay":0.005359217991437581,"remote_delay":0.009643554689745315,"remote_uncertainty":0.001174926758086059,"last_update":{"timestamp":16860021294395965164},"unanswered_polls":0,"poll_interval":4, "nts_cookies": 0,"name":"ntpd-rs.pool.ntp.org:123","address":"158.101.213.248:123","id":4},{"offset":0.000734703149817582,"uncertainty":0.00016960082579627652,"delay":0.01584574813392147,"remote_delay":0.002761840820955541,"remote_uncertainty":0.0009307861330292155,"last_update":{"timestamp":16860021295061957688},"unanswered_polls":0,"poll_interval":4, "nts_cookies": null,"name":"ntpd-rs.pool.ntp.org:123","address":"154.51.12.215:123","id":1},{"offset":0.0002863160335194124,"uncertainty":0.00015027378689271253,"delay":0.009263384390916531,"remote_delay":0.0038757324227773893,"remote_uncertainty":0.000640869140774214,"last_update":{"timestamp":16860021294051732971},"unanswered_polls":0,"poll_interval":4, "nts_cookies": null,"name":"ntpd-rs.pool.ntp.org:123","address":"178.215.228.24:123","id":3}],"servers":[]}"#;

#[test]
fn test_status() {
    let _ = std::fs::remove_file(format!("{CARGO_TARGET_TMPDIR}/status_test_socket"));
    let socket = UnixListener::bind(format!("{CARGO_TARGET_TMPDIR}/status_test_socket")).unwrap();

    spawn(move || {
        let (mut stream, _) = socket.accept().unwrap();
        stream
            .write_all(&(EXAMPLE_SOCKET_OUTPUT.len() as u64).to_be_bytes())
            .unwrap();
        stream.write_all(EXAMPLE_SOCKET_OUTPUT.as_bytes()).unwrap();
    });

    let test_config_contents = format!(
        r#"[observability]
observation-path = "{CARGO_TARGET_TMPDIR}/status_test_socket"

[[source]]
mode = "pool"
address = "ntpd-rs.pool.ntp.org"
count = 4
"#
    );

    let test_config_path = format!("{CARGO_TARGET_TMPDIR}/status_test_config");
    std::fs::write(&test_config_path, test_config_contents.as_bytes()).unwrap();

    let result = test_ntp_ctl_output(&["status", "-c", &test_config_path]);

    assert!(contains_bytes(&result.stdout, b"ntpd-rs.pool.ntp.org"));
    assert!(contains_bytes(
        &result.stdout,
        "0.000286±0.000150(±0.009263)s".as_bytes()
    ));
    assert_eq!(result.status.code(), Some(0));
}

#[test]
fn test_version() {
    let result = test_ntp_ctl_output(&["-v"]);

    assert!(contains_bytes(
        &result.stderr,
        env!("CARGO_PKG_VERSION").as_bytes()
    ));
    assert_eq!(result.status.code(), Some(0));
}

#[test]
fn test_help() {
    let result = test_ntp_ctl_output(&["-h"]);

    assert!(contains_bytes(&result.stdout, b"usage"));
    assert_eq!(result.status.code(), Some(0));
}
