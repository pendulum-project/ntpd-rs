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
The daemon can log messages

## Clocks and synchronization

# CONFIGURATION

## Peer defaults

## Peers

## Servers

## Logging and observability

## Synchronization

## NTS

## Keyset

# SEE ALSO

[ntp-daemon(8)](ntp-daemon.8.md), [ntp-ctl(8)](ntp-ctl.8.md),
[ntp-metrics-exporter(8)](ntp-metrics-exporter.8.md)
