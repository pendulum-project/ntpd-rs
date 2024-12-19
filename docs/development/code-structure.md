# Code structure

This document gives a high-level overview of the structure of ntpd-rs.

## Crates

ntpd-rs is split into several crates with three goals in mind:

 - Split the logic of protocol handling from the details around asynchronous
   network handling
 - Split custom servers needed purely for integration testing from the main
   codebase
 - Limit the scopes where we use unsafe code, ensuring that it is more
   straightforward to verify.

The main `ntp-proto` and `ntpd` crates are set up such that neither contains any
unsafe code. Unsafe code is limited to the (external) `timestamped-socket`, `clock-steering` and `pps-time` crates,
which are purposefully kept small and only offer a safe API.

### ntp-proto

The `ntp-proto` crate contains the main NTP protocol implementation. It
implements:
 - Serialization and deserialization of the on-wire protocol.
 - Packet handling decision logic of the source.
 - Measurement logic of the source, including the per-source filtering.
 - Clock selection, combination and steering algorithms.

This crate only implements the decision and processing logic. It does not
perform the actual communication, nor does it do any of the handling needed to
ensure that source and steering logic is regularly called.

### timestamped-socket

The [`timestamped-socket` crate](https://github.com/pendulum-project/timestamped-socket) provides an async interface to the Linux kernel's
kernel-level network timestamping functionality. It wraps the system calls for
configuring kernel-level timestamping and for retrieving the actual timestamps.
Touching the network layer uses `libc` and is inherently unsafe.

### clock-steering

The [`clock-steering` crate](https://github.com/pendulum-project/clock-steering) wraps the system calls needed for controlling the system
clock. Touching the system clock uses `libc` and is inherently unsafe.

### pps-time

The [`pps-time` crate](https://github.com/pendulum-project/pps-time) wraps the system calls needed to interact with a PPS device. To
interact with PPS devices ioctl system calls are used, which uses `libc` and is inherently unsafe.

### ntpd

The `ntpd` crate contains the code for all three end-user binaries that our
project produces. This includes

- `ntp-daemon` (in `ntpd/src/daemon`)
- `ntp-ctl` (in `ntpd/src/ctl.rs`)
- `ntp-metrics-exporter` (in `ntpd/src/metrics`)

Each of these should mostly contain the actual execution code that calls each
of the previously mentioned crates when required.

## NTP daemon startup and operating sequence.

This section provides a high-level overview of the operation of the NTP daemon,
and how its various tasks are set up, configured and communicate.

Upon startup, the daemon first parses any given command line arguments and uses
these arguments to set up an initial logging system. This early setup of logging
is done to ensure that during reading and parsing of the configuration files the
logging system is available to expose information on errors.

Immediately after, further configuration is read from file and used to generate
the definitive logging system. At this point, the main configuration steps are
completed, and the combined command line and file base configuration is used to
set up at least these kinds of tasks:
 - The main clock steering task.
 - One source task per configured source (remote server).
 - One server task per configured interface on which to serve time.
 - One task for exposing state for observability.
 - One task for dynamic configuration changes.

### Source tasks

The daemon runs a single source task per configured source. This task is
responsible for managing the network connection with that specific source,
sending the poll message to start a clock difference measurement, handling the
response, and doing an initial filtering step over the measurements.

The main loop of the source waits on 3 futures concurrently:
 - A timer, which triggers sending a new poll message.
 - The network socket, receiving a packet here triggers packet processing and
   measurement filtering.
 - A configuration channel, receiving configuration changes.

Should any of these events happen, after handling it the source task then sends
an updated version of the sections of its state needed for clock steering to the
main clock steering task.

### Server task

The daemon runs a single task per interface on which NTP packets are served
(where the any (0.0.0.0) interface counts as a single interface). This task is
responsible for managing the socket for that interface, reading messages and
providing the proper server responses.

The main loop of the server waits on 2 futures concurrently:
 - The network socket
 - A channel providing synchronization state updates

### Clock steering task

The clock steering task listens for the messages from the sources with their
updated state. It keeps a local copy of the last received state from each
source, and also the state of the clock steering algorithm. Some (but not all)
updates from a source indicate that it now has some new measurement data
available. If this happens, the clock steering task triggers a clock algorithm
update.

### Observability task

The observability task is responsible for handling external requests for
insight into the daemon's state. It creates and manages a UNIX socket which can
be queried for information on the state of the daemon.

Once an external program opens a connection to the UNIX socket, the observation
daemon makes a copy of the state of all the sources and of the clock steering
algorithm (it has access to these through a `RwLock` shared with the clock
steering task). It then uses this to generate a JSON bytestream with
information, which it then writes to the connection. Immediately afterwards,
the entire connection is closed.

Note that it never reads from any opened connection on the socket. This is on
purpose, as it limits the amount of attack surface exposed by this task.

### Configuration task

The configuration task changes configuration dynamically at runtime. The task
listens to a socket for new configuration changes. The `ntp-ctl` executable is
an example of how to interact with this socket.

Because this task reads from its socket, it is advised to restrict the
permissions on this socket.

