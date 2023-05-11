# Statime

[![codecov](https://codecov.io/gh/pendulum-project/statime/branch/main/graph/badge.svg?token=QCO6NKS64J)](https://codecov.io/gh/pendulum-project/statime)
[![book](https://shields.io/badge/manual-main-blue)](https://pendulum-project.github.io/statime/)
[![book](https://shields.io/badge/docs.rs-statime-green)](https://pendulum-project.github.io/statime/docs/statime)
[![book](https://shields.io/badge/docs.rs-statime_linux-green)](https://pendulum-project.github.io/statime/docs/statime_linux)

Statime is a work in progress Rust implementation of PTP version 2.1 (IEEE 1588-2019). 
It is currently highly in flux and not yet usable.

<p align="center">
<img width="216px" alt="Statime - PTP in Rust" src="https://tweedegolf.nl/images/statime.jpg" />
</p>

The current state of the project is such that the main binary, when compiled, measures and outputs the time difference to any ptp master clock happening to be sending in the network it listens to.

## Structure

The library has been built in a way to try and be platform-agnostic. To do that, the network and clock have been abstracted.

Many things are event-based where the user needs to call a function on the ptp instance object to let it handle e.g. an incoming network packet.

## Rust version

For compiling this software we advise using the latest version of cargo/rustc as available through rustup. At time of writing this is `1.58.1`.

## Running with elevated privileges

Because of the use of ports 319 and 320 in the PTP protocol, the code here needs to be run as root. It is best to build the code as a non-root user with
```
cargo +nightly build
```
and then run it as root with
```
sudo ./target/debug/linux -i <ETHERNET INTERFACE NAME>
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

# Support our work

The development of Statime is kindly supported by the [NLnet Foundation](https://nlnet.nl).

[SIDN Fonds](https://www.sidnfonds.nl/excerpt) is supporting us with a grant to develop clock devices running Statime and ntpd-rs, in collaboration with SIDN Labs' [TimeNL](https://www.sidnlabs.nl/en/news-and-blogs/timenl-comes-of-age).

We seek involvement and/or sponsoring of interested parties, see the announcement [here](https://twitter.com/tweedegolfbv/status/1504439532971827208).
