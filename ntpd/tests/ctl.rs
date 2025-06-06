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

const EXAMPLE_SOCKET_OUTPUT: &str = r#"{"program":{"version":"1.5.0","build_commit":"9902a64c2082ce5cbf6e5f50bbf8c43992c7dc61-dirty","build_commit_date":"2025-05-15","uptime_seconds":173.020588422,"now":{"timestamp":16992191376115884894}},"system":{"stratum":3,"reference_id":3245285499,"accumulated_steps_threshold":null,"precision":3.814697266513178e-6,"root_delay":0.010765329704332475,"root_variance_base_time":{"timestamp":16992191345545207180},"root_variance_base":1.7857333567999653e-7,"root_variance_linear":5.359051845985771e-10,"root_variance_quadratic":3.62217507174032e-11,"root_variance_cubic":1.0000000000000001e-16,"leap_indicator":"NoWarning","accumulated_steps":0.05176564563339708},"sources":[{"offset":-0.003385264427257996,"uncertainty":0.0026549804030579936,"delay":0.011173352834576124,"remote_delay":0.0002288818359907907,"remote_uncertainty":0.00003051757813210543,"last_update":{"timestamp":16992191339038767615},"unanswered_polls":0,"poll_interval":4,"nts_cookies":null,"name":"ntpd-rs.pool.ntp.org:123","address":"178.239.19.59:123","id":4},{"offset":-0.009082490813239126,"uncertainty":0.00013278494592122383,"delay":0.005744996481981361,"remote_delay":0.005661010743505557,"remote_uncertainty":0.0004577636719815814,"last_update":{"timestamp":16992191345545207180},"unanswered_polls":0,"poll_interval":4,"nts_cookies":null,"name":"ntpd-rs.pool.ntp.org:123","address":"193.111.32.123:123","id":1},{"offset":0.014374783265957326,"uncertainty":0.005806483795355652,"delay":0.0345861502072276,"remote_delay":0.0025329589849647505,"remote_uncertainty":0.001220703125284217,"last_update":{"timestamp":16992191340102798720},"unanswered_polls":0,"poll_interval":4,"nts_cookies":null,"name":"ntpd-rs.pool.ntp.org:123","address":"158.101.216.150:123","id":2},{"offset":-0.008100490087666662,"uncertainty":0.0002707117237780969,"delay":0.0073168433754045616,"remote_delay":0.0034484863289279133,"remote_uncertainty":0.000961303711161321,"last_update":{"timestamp":16992191338247932783},"unanswered_polls":0,"poll_interval":4,"nts_cookies":null,"name":"ntpd-rs.pool.ntp.org:123","address":"77.175.129.186:123","id":3}],"servers":[]}"#;

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
        "+0.014375±0.005806(±0.034586)s".as_bytes()
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

#[test]
fn test_bad_reference_id() {
    // Reference ID is too long

    let test_config_contents = r#"
[[source]]
mode = "pool"
address = "ntpd-rs.pool.ntp.org"
count = 4

[synchronization]
local-stratum = 1
reference-id = "TOO_LONG"
"#;

    let test_config_path = format!("{CARGO_TARGET_TMPDIR}/reference_id_bad_test_config");
    std::fs::write(&test_config_path, test_config_contents.as_bytes()).unwrap();

    let result = test_ntp_ctl_output(&["validate", "-c", &test_config_path]);

    assert!(contains_bytes(&result.stderr, b"up to 4-character string"));
    assert_eq!(result.status.code(), Some(1));
}

#[test]
fn test_good_reference_id() {
    let test_config_contents = r#"
[[source]]
mode = "pool"
address = "ntpd-rs.pool.ntp.org"
count = 4

[synchronization]
local-stratum = 1
reference-id = "GPS"
"#;

    let test_config_path = format!("{CARGO_TARGET_TMPDIR}/reference_id_good_test_config");
    std::fs::write(&test_config_path, test_config_contents.as_bytes()).unwrap();

    let result = test_ntp_ctl_output(&["validate", "-c", &test_config_path]);

    assert!(contains_bytes(&result.stderr, b"good"));
    assert_eq!(result.status.code(), Some(0));
}
