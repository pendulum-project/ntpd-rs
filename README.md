![checks](https://github.com/pendulum-project/ntpd-rs/actions/workflows/checks.yaml/badge.svg?branch=main)
[![codecov](https://codecov.io/gh/pendulum-project/ntpd-rs/branch/main/graph/badge.svg?token=WES1JIYUJH)](https://codecov.io/gh/pendulum-project/ntpd-rs)
[![Crates.io](https://img.shields.io/crates/v/ntpd.svg)](https://crates.io/crates/ntpd)
[![Docs](https://img.shields.io/badge/ntpd--rs-blue?label=docs)](https://docs.ntpd-rs.pendulum-project.org/)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8054/badge)](https://www.bestpractices.dev/projects/8054)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/pendulum-project/ntpd-rs/badge)](https://securityscorecards.dev/viewer/?uri=github.com/pendulum-project/ntpd-rs)

# ntpd-rs

nptd-rs is a tool for synchronizing your computer's clock, implementing the NTP and NTS protocols. It is written in Rust, with a focus on security and stability. It includes both client and server support.

If a feature you need is missing please let us know by opening an issue.

## Documentation

Be sure to check out the [documentation website] as it includes guides on getting started, installation and migration, as well as a high-level overview of the code structure.

## Usage

You can install the packages from the [releases page]. These packages configure ntpd-rs to synchronize your computers clock to servers from the [NTP pool]. After installation, check the status of the ntpd-rs daemon with

```console
$ sudo systemctl status ntpd-rs
```

If ntpd-rs was not started automatically, you can do so now with

```console
$ sudo systemctl start ntpd-rs
```

You should now be able to check the synchronization status with

```console
$ ntp-ctl status
Synchronization status:
Dispersion: 0.000299s, Delay: 0.007637s
Desired poll interval: 16s
Stratum: 4

Sources:
ntpd-rs.pool.ntp.org:123/77.171.247.180:123 (1): +0.000024±0.000137(±0.016886)s
    poll interval: 16s, missing polls: 0
    root dispersion: 0.005905s, root delay:0.016190s
ntpd-rs.pool.ntp.org:123/45.137.101.154:123 (2): +0.000022±0.000081(±0.007414)s
    poll interval: 16s, missing polls: 0
    root dispersion: 0.004517s, root delay:0.005051s
ntpd-rs.pool.ntp.org:123/178.215.228.24:123 (3): +0.000117±0.000091(±0.009162)s
    poll interval: 16s, missing polls: 0
    root dispersion: 0.000549s, root delay:0.004318s
ntpd-rs.pool.ntp.org:123/162.159.200.123:123 (4): +0.000111±0.000076(±0.004066)s
    poll interval: 16s, missing polls: 0
    root dispersion: 0.000351s, root delay:0.003571s

Servers:
```
The top part shows the overal quality of the time synchronization, and the time sources section shows which servers are used as well as offsets and uncertainties of those individual servers.

For more details on how to install and use ntpd-rs, see our [documentation website].

## Roadmap

In Q1 2023 we completed our work on NTS. Our implementation is now
full-featured, it supports NTP client and server with NTS.

Our roadmap for 2024:

* Q2-Q4 2024: Packaging and industry adoption, maintenance & community work
* Q4 2024: NTS Pool (pending funding)

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
implementations of the Network Time Protocol (ntpd-rs) and the Precision Time Protocol (Statime).

In July of 2023 the [Sovereign Tech Fund] invested in Pendulum, securing ntpd-rs development and maintenance in 2023, and maintenance and adoption work in 2024.

![STF](https://tweedegolf.nl/images/logo-stf-blank.png)

[releases page]: https://github.com/pendulum-project/ntpd-rs/releases
[NTP pool]: https://www.ntppool.org
[documentation website]: https://docs.ntpd-rs.pendulum-project.org/
[Prossimo]: https://www.memorysafety.org
[NTP initiative page]: https://www.memorysafety.org/initiative/ntp
[NTP announcement]: https://www.memorysafety.org/blog/ntp-and-nts-have-arrived/
[Project Pendulum]: https://github.com/pendulum-project
[Sovereign Tech Fund]: https://sovereigntechfund.de/en/
