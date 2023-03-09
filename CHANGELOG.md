Master
======

Major Changes
-----
- Changed format of timedata reported for peers to ensure compatibility with different algorithms.
- Implemented (de)serialization of NTP extension fields
- Implemented NTS Key Exchange
- Implemented NTS client functionality and configuration
- Implemented NTS server functionality and configuration
- New and improved clock algorithm

Minor Changes
-----
- Upgraded dependencies
- Refactored internal structure of the code.

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
