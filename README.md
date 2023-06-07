# Statime

[![codecov](https://codecov.io/gh/pendulum-project/statime/branch/main/graph/badge.svg?token=QCO6NKS64J)](https://codecov.io/gh/pendulum-project/statime)
[![book](https://shields.io/badge/manual-main-blue)](https://pendulum-project.github.io/statime/)
[![book](https://shields.io/badge/docs.rs-statime-green)](https://pendulum-project.github.io/statime/docs/statime)
[![book](https://shields.io/badge/docs.rs-statime_linux-green)](https://pendulum-project.github.io/statime/docs/statime_linux)

Statime is a work in progress Rust implementation of PTP version 2.1 (IEEE 1588-2019). It currently implements support for acting as a master and an ordinary or a boundary clock. Note that we are planning a refactor of the codebase, and that the public interface is likely to change.

<p align="center">
<img width="216px" alt="Statime - PTP in Rust" src="https://tweedegolf.nl/images/statime.jpg" />
</p>

The statime-linux crate also provides a binary for linux implementing an ordinary clock. It will need sufficient permissions to change the system clock to use. The easiest way to start it is through sudo: `sudo ./target/debug/statime-linux -i <network_interface>`.

## Structure

The library has been built in a way to try and be platform-agnostic. To do that, the network and clock have been abstracted. The `statime-linux` library provides implementations of these abstractions for linux-based platforms. For other platforms, this needs to be provided by the user. For more details, see [the documentation](https://pendulum-project.github.io/statime/docs/statime)

## Rust version

Statime requires a nigthly version of cargo/rust. The easiest way to obtain these is through [rustup](https://rustup.rs)

## Running with elevated privileges

Because of the use of ports 319 and 320 in the PTP protocol, the code here needs to be run as root. It is best to build the code as a non-root user with
```
cargo +nightly build
```
and then run it as root with
```
sudo ./target/debug/statime-linux -i <ETHERNET INTERFACE NAME>
```

## PTPd setup for testing

PTPd can be used as a ptp master clock for testing. Because of the port usage required by the PTP standard, this master clock must be on a different machine than that used to run the code in this repository. On Ubuntu, it can be installed with
```bash
apt install ptpd
```
You probably wont want to run this continuously as a service, so disable it with
```bash
service ptpd disable
```
Then, to start ptpd, as root run
```bash
ptpd -V -n -M -i <INTERFACE>
```
where `<INTERFACE>` is the netwerk interface you want ptpd to use. Here `-n` disables clock adjustment by ptpd, and `-M` ensures that it runs in master mode only.

# Roadmap

- Q2 2023: PTP master, boundary clock
- Q3 2023: NTP/PTP clock device + development of PTP for Linux (pending funding)
- Q4 2023: Completion of PTP for Linux (pending funding)

# Support our work

The development of Statime is kindly supported by the NGI Assure Fund of the [NLnet Foundation](https://nlnet.nl).

<img style="margin: 1rem 5% 1rem 5%;" src="https://nlnet.nl/logo/banner.svg" alt="Logo NLnet"  width="150px" />
<img style="margin: 1rem 5% 1rem 5%;" src="https://nlnet.nl/image/logos/NGIAssure_tag.svg" alt="Logo NGI Assure" width="150px" />

[SIDN Fonds](https://www.sidnfonds.nl/excerpt) is supporting us with a grant to develop clock devices running Statime and ntpd-rs, in collaboration with SIDN Labs' [TimeNL](https://www.sidnlabs.nl/en/news-and-blogs/an-open-infrastructure-for-sub-millisecond-internet-time).

We seek involvement of interested parties and funding for future work, see [Project Pendulum](https://github.com/pendulum-project).
