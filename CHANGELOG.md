# Changelog

## [1.2.3] - 2024-07-22

### Fixed
- Metrics exporter should wait for an actual request before sending a response

## [1.2.2] - 2024-07-18

### Changed
- Updated dependencies

### Fixed
- Fixed a bug in network change detection that prevented startup on FreeBSD.
- Fixed a bug in leap second flag handling where previous flags weren't explicitly unset.
- Fixed a bug that caused NTS-KE sessions from clients with a large request to hang.
- Fixed a bug that caused NTS-KE error records never to be sent.

## [1.2.0] - 2024-07-11

### Added
- Pool mode sources can be set up to ignore some addresses returned by the pool
- NTP sources use a random client port for every request sent
- The metrics exporter will keep trying to startup while its network interface is not yet available
- Added option for server to only respond to NTS messages.

### Changed
- Updated dependencies
- ntp-udp and ntp-os-clock were replaced by timestamped-socket and clock-steering
- Minor improvements to NTS keyset storage errors
- Loop detection is handled globally instead of per source
- The MSRV was raised to 1.70
- The metrics exporter is better able to handle multiple simultaneous connections
- Pendulum is now part of Trifecta Tech Foundation (copyright was updated)
- Large parts of the daemon code have been refactored to simplify the code

### Fixed
- Metrics would not synchronize if the metrics data was too large
- ntpd-rs would ignore responses from servers implementing NTPv3

## [1.1.3] - 2024-06-28

### Fixed
- Unlimited number of NTS-KE connections could crash ntpd-rs server (CVE-2024-38528)

## [1.1.2] - 2024-02-01

### Fixed
- Fixed tests in ntp-proto to also work outside the repository.

## [1.1.1] - 2024-01-24

### Added
- A work in progress implementation for experimental NTS pools was added

### Changed
- Updated dependencies

### Fixed
- Fixed missing newline at the end of the prometheus metrics export
- Fixed error handling on NTS key exchange sessions
- Small fixes to the experimental NTPv5 draft support

## [1.1.0] - 2023-11-23

### Added
- Server can now be run without permission to change the system clock so long
  as no time sources are configured.
- Experimental NTPv5 draft support was added behind a feature flag (disabled by
  default)

### Changed
- The sources section can be left out of the configuration now.
- When no sources are configured, the daemon will merely state it won't change
  system time, rather than warn
- The MSRV was raised to 1.67

## [1.0.0] - 2023-10-05

### Added
- Man pages have been added to the built packages.
- `ntp-ctl` now has human-friendly output
- Added metrics for NTS packets processed in the server
- Exposed root dispersion and root delay reported by time source as metrics.
- Added `ntp_uptime_seconds` metric, which also includes the software version

### Changed
- Peers have been renamed to sources.
- The configuration has been completely reworked, please check the documentation
  for details. Configuration will not automatically migrate.
- The metrics for observation have been completely reworked.
- Several changes have been made to reduce the number of dependencies.
- Send software timestamping is now enabled by default.
- Hardware timestamping can now only be configured if ntpd-rs is built with the
  `hardware-timestamping` feature (off by default).
- The default observation socket path was changed to `/var/run/ntpd-rs/observe`.
- Upgraded dependencies.
- The command line interface for `ntp-ctl` and `ntp-metrics-exporter` has changed.
- The copyright from the project changed from 'Internet Security Research Group
  and Contributors' to 'Tweede Golf and Contributors'
- The `/etc/ntpd-rs/ntp.toml` file in the deb and rpm packages provided by us is
  now managed by their respective package managers. This may result in your
  config file being overwritten initially, but future upgrades should be handled
  gracefully.
- Added actual ip address of ntp server to observable data. The address field has
  been renamed for this.

### Fixed
- Fix bug around handling of leap second indicators.
- Fixed bug around handling of accumulated step thresholds.
- Fixed incorrect reference id being used by server.
- Fixed user creation in packages.
- Fixed peer trying to request more cookies than it can encode in it's packet buffer.
- Fixed server not sending nts naks when receiving nts packets it can't decrypt.
- Fixed source poll interval not being updated in stats.

### Removed
- Removed support for the RFC5905 algorithm.
- Sources and servers can no longer be configured via the command line.
- Logging can now only be configured via a log level, no other filtering is
  possible.
- The daemon control socket has been removed, the daemon can no longer be
  reconfigured at runtime.

## [0.3.7] - 2023-08-23

### Changed
- Upgraded dependencies.

### Removed
- Removed sentry support.

### Fixed
- Upgraded webpki to deal with denial of service security issue during startup.

## [0.3.6] - 2023-06-30

### Major Changes
- Restructured configuration. See CONFIGURATION.md.

### Minor Changes
- Additional example configuration for freeBSD.
- Slight improvements to clock algorithm.
- Upgraded dependencies.
- Clock now synchronizes faster on startup.
- Added support for listening for NTS-KE on multiple ip/port combinations.

### Bug fixes
- Fixed bug that caused ntp-ctl validate to not print warnings on the
  configuration, only parsing errors.
- Fixed bug in nts parsing that caused NTS to be entirely inoperable.

## [0.3.5] - 2023-06-15

No changes compared with 0.3.4, needed due to technical difficulties in release
process.

## [0.3.4] - 2023-06-15

### Minor Changes
- Fixed bug that caused nts-providing servers to fail after key rotation (which
  by default happens daily).
- Upgraded dependencies.
- Fix bug in package installers that caused us to overwrite configuration on
  update.
- Removed dependency on Axum in prometheus exporter.
- Improved measurement code to deal better with external programs changing the
  clock.
- Removed some spurious warnings around server strata.

## [0.3.3] - 2023-05-25

### Major Changes
- Compilation with musl libc on linux (thanks @sanmai-NL)
- Compilation support for macos (thanks @andrewaylett)
- Compilation support for freebsd (thanks @valpackett)

### Minor Changes
- Fix for invalid NTS cookie decoding that could cause a server panic
- Improved mechanism for waiting on timestamps arriving the error queue
- Added security policy
- Upgraded dependencies
- Remove exitcode dependency
- Remove direct prometheus dependency from ntp-daemon

## [0.3.2] - 2023-04-17

### Minor Changes
- Updated readme and documentation

## [0.3.1] - 2023-04-17

### Major Changes
- Our new and improved clock algorithm is now the default
- Implemented (de)serialization of NTP extension fields
- Implemented NTS Key Exchange
- Implemented NTS client functionality and configuration
- Implemented NTS server functionality and configuration
- Changed format of timedata reported for peers to ensure compatibility with
  different algorithms.

### Minor Changes
- Upgraded dependencies
- Refactored internal structure of the code.

## [0.2.1] - 2022-12-01

### Major Changes
- Pool support.
- Prometheus exporter.

### Minor Changes
- Upgraded dependencies
- Refactored internal structure of the code.

## [0.2.0] - 2022-07-29

### Major Changes
- Implemented support for running an NTP server.
- Renamed `ntp-client` binary to `ntp-ctl`.

### Minor Changes
- Made poll interval range and initial value configurable.
- Minor improvements to timestamping of received and sent packets.
- Minor improvements to log output, particularly around attribution of events to
  specific peers.
- Upgraded dependencies

### Bugfixes
- Fixed a number of bugs around poll interval adjustment.
- Fixed a bug in peer dispersion calculation which resulted in overly
  pessimistic dispersion estimates.

[1.2.3]: https://github.com/pendulum-project/ntpd-rs/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/pendulum-project/ntpd-rs/compare/v1.2.0...v1.2.2
[1.2.0]: https://github.com/pendulum-project/ntpd-rs/compare/v1.1.3...v1.2.0
[1.1.3]: https://github.com/pendulum-project/ntpd-rs/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/pendulum-project/ntpd-rs/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/pendulum-project/ntpd-rs/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/pendulum-project/ntpd-rs/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/pendulum-project/ntpd-rs/compare/v0.3.7...v1.0.0
[0.3.7]: https://github.com/pendulum-project/ntpd-rs/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/pendulum-project/ntpd-rs/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/pendulum-project/ntpd-rs/compare/v0.3.3...v0.3.5
[0.3.4]: https://github.com/pendulum-project/ntpd-rs/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/pendulum-project/ntpd-rs/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/pendulum-project/ntpd-rs/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/pendulum-project/ntpd-rs/compare/v0.2.1...v0.3.1
[0.2.1]: https://github.com/pendulum-project/ntpd-rs/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/pendulum-project/ntpd-rs/releases/tag/v0.2.0
