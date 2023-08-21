![checks](https://github.com/pendulum-project/ntpd-rs/actions/workflows/build.yaml/badge.svg?branch=main)
[![codecov](https://codecov.io/gh/pendulum-project/ntpd-rs/branch/main/graph/badge.svg?token=WES1JIYUJH)](https://codecov.io/gh/pendulum-project/ntpd-rs)
[![Crates.io](https://img.shields.io/crates/v/ntpd.svg)](https://crates.io/crates/ntpd)


# ntpd-rs

ntpd-rs is an NTP implementation written in Rust, with a focus on security and
stability. It includes client and server functionality and supports NTS.

If a feature you need is missing please let us know by opening an issue.

## Installation

The recommended way of installing ntpd-rs is with the pre-built packages from
the [releases page]. The installers automatically handle setting up users,
permissions and configuration. Alternatively, you can use `cargo install ntpd`
or build from source by cloning the repository yourself.

### Build from source

Currently, ntpd-rs only supports Linux-based operating systems. Our current
testing only targets Linux kernels after version 5.0.0, older kernels may work
but this is not guaranteed.

ntpd-rs is written in rust. We strongly recommend using [rustup] to install a
rust toolchain, because the version provided by system package managers tends to
be out of date. Be sure to use a recent version of the rust compiler. To build
ntpd-rs run

```sh
cargo build --release
```

This produces a `ntp-daemon` binary at `target/release/ntp-daemon`, which is the
main NTP daemon. Before running the ntpd-rs daemon, make sure that no other NTP
daemons are running. E.g. when chrony is running

```sh
systemctl stop chronyd
```

The ntpd-rs daemon requires elevated permissions to change the system clock.

```sh
sudo ./target/release/ntp-daemon -c ./ntp.toml
```

By default, at least 3 peer servers are needed for the algorithm to change the
time. After a few minutes you should start to see messages indicating the offset
of your machine from the server.

```
2023-04-11T10:06:24.847375Z  INFO ntp_proto::algorithm::kalman: Offset: 1.7506740305607742+-12.951528666965439ms, frequency: 8.525844072881435+-5.089483351832892ppm
2023-04-11T10:06:25.443852Z  INFO ntp_proto::algorithm::kalman: Offset: 1.8947020578044949+-12.981792974220694ms, frequency: 7.654657944152439+-3.3911904299378386ppm
2023-04-11T10:06:25.443979Z  INFO ntp_proto::algorithm::kalman: Changed frequency, current steer 4.26346751414286ppm, desired freq 0ppm
```

A complete description of how the daemon can be configured can be found in the
documentation found in the [documentation](./docs/).

## Minimum supported rust version

We make no guarantees about supporting older versions of rust. When building
from source (either manually or with `cargo install`) use the latest rust
version to prevent issues.

We are committed to keep ntpd-rs working on at least the latest stable and beta
compilers. Beyond this, we keep track of the current minimum rust version needed
to compile our code for purposes of documentation. However, right now we do not
have a policy guaranteeing a minimum amount of time we will support a stable
rust release beyond the 6 weeks during which it is the latest stable version.

Please note that the Rust project only supports the latest stable rust release.
As this is the only release that will receive any security updates, we STRONGLY
recommend using the latest stable rust version for compiling ntpd-rs for daily
use.

## Package substructure

Currently, the code is split up into several separate crates:

* `ntp-proto` contains the packet parsing and the algorithms needed for clock
  selection, filtering and steering.
* `test-binaries` contains a number of simple NTP servers that can be used for
  testing (see below).
* `ntp-os-clock` contains the unsafe code needed to interface with system
  clocks.
* `ntp-udp` contains the unsafe code needed to deal with timestamping on the
  network layer.
* `ntpd` contains the entrypoints for all our binaries and the code for the
  daemon (`ntp-daemon`), control client (`ntp-ctl`) and OpenMetrics/prometheus
  exporter (`ntp-metrics-exporter`).


All unsafe code is contained within the `ntp-os-clock` and `ntp-udp` packages,
which are kept as small as possible. All interfaces exposed by these crates
should be safe. For a more detailed description of how ntpd-rs is structured,
see the [development documentation](./docs/development/).

## Test Binaries

This crate contains extremely limited NTP servers for testing purposes

* `demobilize-server` always sends the DENY kiss code, the client must
  demobilize this association
* `rate-limit-server` forces an increase of the poll interval to 32 seconds

## Roadmap

In Q1 2023 we completed our work on NTS. Our implementation is now
full-featured, it supports NTP client and server with NTS.

Our roadmap for 2023:

* Q2 2023: Adoption work, improved packaging, FreeBSD support
* Q3 2023: Stable release (pending funding)
* Q4 2023: Development work on experimental features, NTS pool, NTPv5 (pending
  funding)

We seek sponsorship for features and maintenance to continue our work. Contact
us via pendulum@tweedegolf.com if you are interested!

## History

### 2022

The project originates from ISRG's project [Prossimo], as part of their mission
to achieve memory safety for the Internet's most critical infrastructure.

<img alt="Prossimo" src="https://www.memorysafety.org/images/Prossimo%20Brand%20Assets/Prossimo%20Horizontal%20Full%20Color.svg" width="250px"/>

Prossimo funded the initial development of the NTP client and server, and NTS
support. The [NTP initiative page] on Prossimo's website tells the story.

### 2023

After completion of the initial development, the project's ownership moved from
Prossimo to Tweede golf in April 2023. See the [NTP announcement] for more
information.

Tweede golf is the long-term maintainer of ntpd-rs, that is now part of Tweede
golf's [Project Pendulum]. Pendulum is building modern, open-source
implementations of the Network Time Protocol and the Precision Time Protocol.

![STF](https://tweedegolf.nl/images/logo-stf-blank.png)

[releases page]: https://github.com/pendulum-project/ntpd-rs/releases
[rustup]: https://rustup.rs
[Prossimo]: https://www.memorysafety.org
[NTP initiative page]: https://www.memorysafety.org/initiative/ntp
[NTP announcement]: https://www.memorysafety.org/blog/ntp-and-nts-have-arrived/
[Project Pendulum]: https://github.com/pendulum-project
