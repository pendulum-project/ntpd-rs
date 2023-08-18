<!-- ---
title: NTP.TOML(5) ntpd-rs 0.3.6 | ntpd-rs
--- -->

# NAME

`ntp.toml` - configuration file for the ntpd-rs ntp-daemon

# DESCRIPTION

Configuration of ntpd-rs happens in the `ntp.toml` configuration format. The
toml format is in lots of ways similar to a simple ini with several extensions
allowing a json-like syntax.

The ntpd-rs configuration file consists of several sections, each of which
configuring a separate part of the ntp-daemon process. Each of the secions is
described in the rest of this document. Many settings will have defaults,
which will be indicated by each configuration setting shown.

For those familiar with the NTP protocol: ntpd-rs only supports unicast
client-server connections and the concepts in ntpd-rs are all built up around
that concept. Most NTP traffic, especially across the public internet, almost
exclusively uses this mode, so it is not considered a practical limitation for
most scenarios.

# CONCEPTS

## Peer
A peer represents a set of one or more connections to time sources (another
NTP server) where the daemon retrieves time information from. The time
information from these peers are then filtered and combined to update the local
clock. The daemon can have multiple of these peer sets configured to allow for
a wider range of time sources. When ntp-daemon is used in a client only
setup the configuration only contains peer configurations and no server
configurations.

## Server
A server distributes time information to clients who request it. A server
listens on a single socket address for client packets and responds to them. The
daemon can listen on multiple sockets by creating multiple server
configurations. Generally, when NTP is configured as a server it also has one
or more peer configurations from where time is retrieved. The daemon currently
does not have support for local time sources, if no peers are configured, then
another process should be in place to discipline the local system clock.

## NTS and keysets
NTS, Network Time Security, is a protocol that uses a TLS handshake to
exchange secrets to allow verifying that responses from an NTP server have not
been tampered with. The daemon supports running NTS in both server and client
(peer) connections. For the server functionality a key exchange server also
needs to be configured. Currently only an internal key exchange server is
supported. The NTP server and TLS key exchange server of the ntp-daemon both
need to be aware of a shared set of keys, these keys are called the keyset.

## Logging and observability
The daemon can log messages about how it is operating in different logging
levels. These log messages come in several priorities (from low to high):
*trace*, *debug*, *info*, *warn* and *error*. You can use these log messages to
monitor the daemon. The log messages are outputted on stdout.

Aside from logging, you can use the observability metrics to get semi-realtime
information about several key metrics for both the client and server part of
the daemon. These metrics are exposed via the `ntp-ctl` CLI utility, or by using
our prometheus / openmetrics exporter.

## Clocks and synchronization
Of course the main reason for running an NTP daemon is to get accurate time
information. This should result in the daemon adjusting your system clock. The
algorithm that is used to combine the information from several peers and update
the system clock can be configured using the synchronization section in the
configuration file.

# CONFIGURATION

## `[peer_defaults]`
Some values are shared between all peers in the daemon. You can configure these
in the `[peer_defaults]` section.

`poll-interval-limits` = { `min` = *min*, `max` = *max* } (**{ min = 4, max = 10}**)
:   Specifies the limit on how often a peer is queried for a new time. For most
    instances the defaults will be adequate. The min and max are given as the
    log2 of the number of seconds (i.e. two to the power of the interval). An
    interval of 4 equates to 32 seconds, 10 results in an interval of 1024
    seconds. If specified, both min and max must be specified.

`initial-poll-interval` = *interval* (**4**)
:   Initial poll interval used on startup. The value is given as the log2 of
    the number of seconds (i.e. two to the power of the interval). The default
    value of 4 results in an interval of 32 seconds.

## `[[peer]]`
Any number of peers can be configured by repeating a `[[peer]]` section (note
the double brackets) for as many times as required. Each peer can be configured
to connect to a specific remote location.

`mode` = *mode*
:   Specify one of the peer modes that ntpd-rs supports: `simple`, `pool` or
    `nts`.

`address` = *address*
:   Specify the remote address of the peer. For simple peers this will be the
    remote address of the NTP server. For pools, this will be the DNS address
    of the NTP pool and for nts this will be the address of the key exchange
    server. The server address may include a port number by appending a colon
    (`:`) followed by a port number. If not specified the daemon will connect
    to `simple` and `pool` servers via port *123*, for `nts` peers the default
    port is *4460*.

`certificate_authority` = *cert*
:   Can only be set on peers with the `nts` mode. Path to a certificate for an
    additional certificate authority to use, aside from the certificate
    authorities specified by the system configuration. Note that this cannot be
    used to specify a self signed certificate.

`count` = *number* (**4**)
:   Can only be set on peers with the `pool` mode. Optionally specifies an
    alternative for the maximum number of peers that will be retrieved from the
    pool. The daemon will keep retrying to get more peers from the pool when
    connections are lost, up to the maximum specified by this configuration
    value.

## `[[server]]`
Any number of servers can be configured by repeating a `[[server]]` section
(note the double brackets) for as many times as required. Each server can serve
a specific socket address. Servers always serve the system clock time.

`listen` = *socketaddr*
:   Address of a socket on which the server should listen for incoming NTP
    requests. Specified as an interface IP address, a colon and a port number.
    Both IPv4 and IPv6 are supported. For example to listen on localhost port
    123 in IPv4 you can use `127.0.0.1:123`. You can listen on all available
    network interfaces at once using `0.0.0.0:123` for IPv4 or `[::]:123` for
    IPv6.

## `[observability]`

## `[synchronization]`

## `[[nts-ke-server]]`

## `[keyset]`

# SEE ALSO

[ntp-daemon(8)](ntp-daemon.8.md), [ntp-ctl(8)](ntp-ctl.8.md),
[ntp-metrics-exporter(8)](ntp-metrics-exporter.8.md)
