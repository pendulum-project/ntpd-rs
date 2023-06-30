Master
======

Bug fixes
-----
- Fixed bug that caused ntp-ctl validate to not print warnings on the configuration, only parsing errors.

Version 0.3.5
======

No changes compared with 0.3.4, needed due to technical difficulties in release process.

Version 0.3.4
======

Minor Changes
-----
- Fixed bug that caused nts-providing servers to fail after key rotation (which by default happens daily).
- Upgraded dependencies.
- Fix bug in package installers that caused us to overwrite configuration on update.
- Removed dependency on Axum in prometheus exporter.
- Improved measurement code to deal better with external programs changing the clock.
- Removed some spurious warnings around server strata.

Version 0.3.3
======

Major Changes
-----
- Compilation with musl libc on linux (thanks @sanmai-NL)
- Compilation support for macos (thanks @andrewaylett)
- Compilation support for freebsd (thanks @valpackett)

Minor Changes
------
- Fix for invalid NTS cookie decoding that could cause a server panic
- Improved mechanism for waiting on timestamps arriving the error queue
- Added security policy
- Upgraded dependencies
- Remove exitcode dependency
- Remove direct prometheus dependency from ntp-daemon

Version 0.3.2
======

Minor Changes
------
- Updated readme and documentation

Version 0.3.1
======

Major Changes
-----
- Our new and improved clock algorithm is now the default
- Implemented (de)serialization of NTP extension fields
- Implemented NTS Key Exchange
- Implemented NTS client functionality and configuration
- Implemented NTS server functionality and configuration
- Changed format of timedata reported for peers to ensure compatibility with different algorithms.

Minor Changes
-----
- Upgraded dependencies
- Refactored internal structure of the code.

Version 0.3.0
======
Unreleased

Version 0.2.1
======

Major Changes
-----
- Pool support.
- Prometheus exporter.

Minor Changes
-----
- Upgraded dependencies
- Refactored internal structure of the code.

Version 0.2.0
======

Major Changes
-----
- Implemented support for running an NTP server.
- Renamed `ntp-client` binary to `ntp-ctl`.

Minor Changes
-----
- Made poll interval range and initial value configurable.
- Minor improvements to timestamping of received and sent packets.
- Minor improvements to log output, particularly around attribution of events to specific peers.
- Upgraded dependencies

Bugfixes
-----
- Fixed a number of bugs around poll interval adjustment.
- Fixed a bug in peer dispersion calculation which resulted in overly pessimistic dispersion estimates.
