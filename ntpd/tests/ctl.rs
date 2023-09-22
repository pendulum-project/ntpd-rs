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

const EXAMPLE_SOCKET_OUTPUT: &str = r#"{"program":{"version":"1.0.0","build_commit":"test","build_commit_date":"2000-01-01","uptime_seconds":0.12345},"system":{"stratum":3,"reference_id":3243240718,"accumulated_steps_threshold":null,"poll_interval":4,"precision":3.814697266513178e-6,"root_delay":0.004877627828362777,"root_dispersion":0.0004254912492878482,"leap_indicator":"Unknown","accumulated_steps":0.002842015820285775},"sources":[{"Observable":{"offset":0.00031014974236259,"uncertainty":0.000050753355038062054,"delay":0.0036874422812106654,"remote_delay":0.0011901855471521117,"remote_uncertainty":0.019378662113886946,"last_update":{"timestamp":16760961381687937893},"unanswered_polls":0,"poll_interval":4,"address":"1.2.3.4:123","name":"ntpd-rs.pool.ntp.org:123","id":3}},{"Observable":{"offset":0.0003928544466367118,"uncertainty":0.00005519413390550626,"delay":0.004574143328837618,"remote_delay":0.001602172851935535,"remote_uncertainty":0.0004425048829155287,"last_update":{"timestamp":16760961379467247810},"unanswered_polls":0,"poll_interval":4,"address":"5.6.7.8:123","name":"ntpd-rs.pool.ntp.org:123","id":1}},{"Observable":{"offset":0.00043044891218432433,"uncertainty":0.00005691661500765863,"delay":0.004752595444385101,"remote_delay":0.001602172851935535,"remote_uncertainty":0.03733825684463099,"last_update":{"timestamp":16760961371126323413},"unanswered_polls":0,"poll_interval":4,"address":"9.10.11.12:123","name":"ntpd-rs.pool.ntp.org:123","id":2}},{"Observable":{"offset":-0.0019038764298669707,"uncertainty":0.00016540312212086355,"delay":0.007399475902179134,"remote_delay":0.01371765137038139,"remote_uncertainty":0.0014495849612750078,"last_update":{"timestamp":16760961373841849724},"unanswered_polls":0,"poll_interval":4,"address":"13.14.15.16:123","name":"ntpd-rs.pool.ntp.org:123","id":4}}],"servers":[]}"#;

#[test]
fn test_status() {
    let _ = std::fs::remove_file(format!("{CARGO_TARGET_TMPDIR}/status_test_socket"));
    let socket = UnixListener::bind(format!("{CARGO_TARGET_TMPDIR}/status_test_socket")).unwrap();

    spawn(move || {
        let (mut stream, _) = socket.accept().unwrap();
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
        "0.000310±0.000051(±0.003687)s".as_bytes()
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
