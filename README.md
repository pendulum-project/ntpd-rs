![checks](https://github.com/memorysafety/ntpd-rs/actions/workflows/build.yaml/badge.svg)[![codecov](https://codecov.io/gh/memorysafety/ntpd-rs/branch/main/graph/badge.svg?token=WES1JIYUJH)](https://codecov.io/gh/memorysafety/ntpd-rs)

# NTPD-rs

NTPD-rs is an implementation of NTP completely written in Rust, with a focus on exposing a minimal attack surface. The project is currently in an early stage, and is not yet suitable for daily use. However, you can try it out if you are comfortable with running pre-release software.

## Quick start

Currently, NTPD-rs only supports Linux-based operating systems. Our current testing only targets Linux kernels after version 5.0.0, older kernels may work but this is not guaranteed.

NTPD-rs is written in rust, and requires cargo 1.60.0 at a minimum to be built. We strongly recommend using [rustup](https://rustup.rs) to install a rust toolchain, because the version provided by system package managers tends to be out of date.

To build NTPD-rs run
```sh
cargo build --release
```
This produces a binary `ntp-daemon` in the `target/release` folder, which is the main NTP daemon.

Before running the NTPD-rs daemon, make sure that no other NTP daemons are running. E.g. when chrony is running
```sh
systemctl stop chronyd
```

The NTPD-rs daemon requires elevated permissions to change the system clock. It can be tested against a server in the [NTP pool](https://ntppool.org)
```sh
sudo ./target/release/ntp-daemon -p pool.ntp.org
```
After a few minutes you should start to see messages indicating the offset of your machine from the server. A complete description of how the daemon can be configured can be found in the [configuration documentation](CONFIGURATION.md)

## Naming

We are currently looking for a better name for this project. Suggestions for this are welcome.

## Package substructure

Currently, the code is split up into five separate crates:
 - `ntp-proto` contains the packet parsing and the algorithms needed for clock selection, filtering and steering.
 - `ntp-daemon` contains the main NTP daemon, and deals with orchestrating the networking and configuration.
 - `test-binaries` contains a number of simple NTP servers that can be used for testing (see below).
 - `ntp-os-clock` contains the unsafe code needed to interface with system clocks.
 - `ntp-udp` contains the unsafe code needed to deal with timestamping on the network layer.

All unsafe code is contained within the `ntp-os-clock` and `ntp-udp` packages, which are kept as small as possible. All interfaces exposed by these crates should be safe. For a more detailed description of how NTPD-rs is structured, see the [development documentation](DEVELOPMENT.md).

## Test Binaries

This crate contains extremely limited NTP servers for testing purposes

* `demobilize-server` always sends the DENY kiss code, the client must demobilize this association
* `rate-limit-server` forces an increase of the poll interval to 32 seconds

## Minimum supported rust version

We try to keep NTPD-rs working on at least the latest stable, beta and nightly rust compiler. Beyond this, we keep track of the current minimum rust version needed to compile our code for purposes of documentation. However, right now we do not have a policy guaranteeing a minimum amount of time we will support a stable rust release beyond the 6 weeks during which it is the latest stable version.

Please note that the Rust project only supports the latest stable rust release. As this is the only release that will receive any security updates, we STRONGLY recommend using the latest stable rust version for compiling NTPD-rs for daily use.
