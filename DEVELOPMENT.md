# ntpd-rs development guide

This document gives a high-level overview of the structure of ntpd-rs.

## Crates

ntpd-rs is split into several crates with three goals in mind:

 - Split the logic of protocol handling from the details around asynchronous network handling
 - Split custom servers needed purely for integration testing from the main codebase
 - Limit the scopes where we use unsafe code, ensuring that it is more straightforward to verify.

The main `ntp-proto` and `ntp-daemon` crates are setup such that neither contains any unsafe code. Unsafe code is limited to the `ntp-udp` and `ntp-clock` crates, which are purposefully kept small and only offer a safe API.

### ntp-proto

The `ntp-proto` crate contains the main NTP protocol implementation. It implements:
 - Serialization and deserialization of the on-wire protocol.
 - Packet handling decision logic of the peer.
 - Measurement logic of the peer, including the per-peer filtering.
 - Clock selection, combination and steering algorithms.

This crate only implements the decision and processing logic. It does not perform the actual communication, nor does it do any of the handling needed to ensure that peer and steering logic is regularly called.

### ntp-daemon

The `ntp-daemon` crate contains the code orchestrating the running of the daemon. At startup, it loads configuration, and then starts the following (parallel) tasks:
 - A system task responsible for aggregating measurements and actually adjusting the clock
 - One task per peer connection responsible for managing the process of measuring delays to a remote peer and doing the initial per-peer filtering on those measurements
 - One task responsible for exposing state over the observability socket
 - One task responsible for handling dynamic changes in configuration commanded over the configuration socket.

For each of these tasks, the daemon crate contains the logic for input/output and handing of relevant communications between the tasks. In particular, all code needed to deal with the async and parallel execution environment lives here. The implementation of the actual parsing of network packets, and the steering and filtering algorithms is handled by the `ntp-proto` crate.

### ntp-ctl

The `ntp-ctl` crate communicates with the daemon's observability and configuration tasks (see below) to provide information about the daemon's state and change configuration options at runtime.

### ntp-udp

The `ntp-udp` crate provides an async interface to the Linux kernel's kernel-level network timestamping functionality. It wraps the system calls for configuring kernel-level timestamping and for retrieving the actual timestamps. Touching the network layer uses `libc` and is inherently unsafe.

### ntp-clock

The `ntp-clock` crate wraps the system calls needed for controlling the system clock. Touching the system clock uses `libc` and is inherently unsafe.

### test-binaries

The `test-binaries` crate contains several binaries that are useful for doing integration tests. This includes, among other things
 - A local test server that always replies with a `DENY` kiss code
 - A local test server that enforces a stricter-than-typical rate limit from the client.

If you need an additional program to aid in (manual) integration testing, this is the crate to add it to.

## NTP daemon startup and operating sequence.

This section provides a high-level overview of the operation of the ntp daemon, and how its various tasks are setup, configured and communicate.

Upon startup, the daemon first parses any given command line arguments and uses these arguments to setup an initial logging system. This early setup of logging is done to ensure that during reading and parsing of the configuration files the logging system is available to expose information on errors.

Immediately after, further configuration is read from file and used to generate the definitive logging system. At this point, the main configuration steps are completed, and the combined command line and file base configuration is used to setup 4 tasks:
 - The main clock steering task.
 - One peer task per configured peer (remote server).
 - One server task per configured interface on which to serve time.
 - One task for exposing state for observability.
 - One task for dynamic configuration changes.

### Peer tasks

The daemon runs a single peer task per configured peer. This task is responsible for managing the network connection with that specific peer, sending the poll message to start a clock difference measurement, handling the response, and doing an initial filtering step over the measurements.

The main loop of the peer waits on 3 futures concurrently:
 - A timer, which triggers sending a new poll message.
 - The network socket, receiving a packet here triggers packet processing and measurement filtering.
 - A configuration channel, receiving configuration changes.

Should any of these events happen, after handling it the peer task then sends an updated version of the sections of its state needed for clock steering to the main clock steering task.

### Server task

The daemon runs a single task per interface on which ntp packets are served (where the any (0.0.0.0) interface counts as a single interface). This task is responsible for managing the socket for that interface, reading messages and providing the proper server responses.

The main loop of the server waits on 2 futures concurrently:
 - The network socket
 - A channel providing synchronization state updates

### Clock steering task

The clock steering task listens for the messages from the peers with their updated state. It keeps a local copy of the last received state from each peer, and also the state of the clock steering algorithm. Some (but not all) updates from a peer indicate that it now has some new measurement data available. If this happens, the clock steering task triggers a clock algorithm update.

### Observability task

The observability task is responsible for handling external requests for insight into the daemon's state. It creates and manages a UNIX socket which can be queried for information on the state of the daemon.

Once an external program opens a connection to the UNIX socket, the observation daemon makes a copy of the state of all the peers and of the clock steering algorithm (it has access to these through a `RwLock` shared with the clock steering task). It then uses this to generate a JSON bytestream with information, which it then writes to the connection. Immediately afterwards, the entire connection is closed.

Note that it never reads from any opened connection on the socket. This is on purpose, as it limits the amount of attack surface exposed by this task.

### Configuration task

The configuration task changes configuration dynamically at runtime. The task listens to a socket
for new configuration changes. The `ntp-ctl` executable is an example of how to interact with
this socket.

Because this task reads from its socket, it is advised to restrict the permissions on this socket.

## Releasing

New releases are created by using `cargo-release`. To create a new release make
sure you have it installed and then run `cargo release [level]` with level being
one of `alpha`, `beta`, `rc`, `patch`, `minor` or `major`. To make a new release
make sure you have access to publish new releases and make sure that you are on
the `main` branch and have access to push new commits to that branch. Make sure
to pick the correct release level depending on the contents of the release. Also
make sure that the changelog is up-to-date with the most recent changes. By
default `cargo release` will run in dry-run mode and run some checks to make
sure that things probably work as expected. You are required to sign the commit
and tag you will make, so make sure that gpg is working as intended. Once ready,
you can run `cargo release [level] --execute` to actually build and commit.

Once this command completes, new releases should have been published to
crates.io, but please verify manually that everything is where it is supposed to
be. A new commit and tag will also have been pushed to the repository. This
should also trigger a release build on github which will publish binaries on
github under a new release.