<!-- ---
title: NTP.TOML(5) ntpd-rs 1.3.0 | ntpd-rs
--- -->

# NAME

`ntp.toml` - configuration file for the ntpd-rs ntp-daemon

# DESCRIPTION

Configuration of ntpd-rs happens in the `ntp.toml` configuration format. The
toml format is in lots of ways similar to a simple ini with several extensions
allowing a json-like syntax.

The ntpd-rs configuration file consists of several sections, each of which
configures a separate part of the ntp-daemon process. Each of the sections is
described in the rest of this document. Many settings will have defaults, which
will be indicated by each configuration setting shown.

The ntp daemon only supports unicast client-server connections. Most NTP
traffic, especially across the public internet, almost exclusively uses this
mode, so it is not considered a practical limitation for most scenarios.

# SOURCE MODES
Different types of sources (see the section below for details) are supported by
the ntp daemon. To set the type of the source, you can configure the mode field
with any of these options:

`server`
:   A server source connects to a single specific NTP server. If a connection is
    lost, attempts will be made to reconnect to the source.

`pool`
:   A pool source retrieves multiple NTP servers by resolving a hostname via
    DNS. It then attempts to connect to multiple of these servers at the same
    time. If a connection is lost, a new server will be retrieved from the pool.

`nts`
:   Connect to a single Network Time Security (NTS) source. The NTS protocol
    uses a TLS handshake to exchange secrets with a server to allow verifying
    that NTP messages have not been tampered with. Note that the TLS protocol
    requires that both the client and server have a rough idea of the current
    time.

# CONFIGURATION

## `[source-defaults]`
Some values are shared between all sources in the daemon. You can configure
these in the `[source-defaults]` section.

`poll-interval-limits` = { `min` = *min*, `max` = *max* } (**{ min = 4, max = 10}**)
:   Specifies the limit on how often a source is queried for a new time. For
    most instances the defaults will be adequate. The min and max are given as
    the log2 of the number of seconds (i.e. two to the power of the interval).
    An interval of 4 equates to 32 seconds, 10 results in an interval of 1024
    seconds. If specified, both min and max must be specified.

`initial-poll-interval` = *interval* (**4**)
:   Initial poll interval used on startup. The value is given as the log2 of
    the number of seconds (i.e. two to the power of the interval). The default
    value of 4 results in an interval of 32 seconds.

## `[[source]]`
Each `[[source]]` is a set of one or more time sources for the daemon to
retrieve time information from. Any number of sources can be configured by
repeating a `[[source]]` section (note the double brackets) for as many times as
required. Each source can be configured to connect to a specific remote
location. Multiple modes for connecting to sources are supported. If less than
`minimum-agreeing-sources` time sources have been configured, no time will be
synchronized to the local clock. Note that a pool counts as multiple time
sources.

`mode` = *mode*
:   Specify one of the source modes that ntpd-rs supports: `server`, `pool` or
    `nts`. For a description of the different source modes, see the
    *SOURCE MODES* section.

`address` = *address*
:   Specify the remote address of the source. For server sources this will be
    the remote address of the NTP server. For pools, this will be the DNS
    address of the NTP pool and for nts this will be the address of the key
    exchange server. The server address may include a port number by appending a
    colon (`:`) followed by a port number. If not specified the daemon will
    connect to `server` and `pool` servers via port *123*, for `nts` sources the
    default port is *4460*.

`certificate-authority` = *cert*
:   Can only be set on sources with the `nts` mode. Path to a certificate for an
    additional certificate authority to use, aside from the certificate
    authorities specified by the system configuration. Note that this cannot be
    used to specify a self signed certificate.

`count` = *number* (**4**)
:   Can only be set on sources with the `pool` mode. Specifies the maximum
    number of servers that the daemon will attempt to connect to from a pool.
    The daemon will keep retrying to get more sources from the pool when
    connections are lost, up to the maximum specified by this configuration
    value.

`ignore` = *ip addresses*
:   `pool` mode only. Specifies a list of ip addresses of servers in the pool
    which should not be used. For example: `["127.0.0.1"]`. Empty by default.

## `[[server]]`
The NTP daemon can be configured to distribute time via any number of
`[[server]]` sections. If no such sections have been defined, the daemon runs in
a client only mode. Any number of servers can be configured by repeating the
`[[server]]` section (note the double brackets) for as many times as required.
Each server can serve a specific socket address or listen on all available
network interfaces on a specific port. Servers always serve the system clock
time.

`listen` = *socketaddr*
:   Address of a UDP socket on which the server should listen for incoming NTP
    requests. Specified as an interface IP address, a colon and a port number.
    The standard port number for NTP is UDP port 123. Both IPv4 and IPv6 are
    supported. For example to listen on localhost port 123 in IPv4 you can use
    `127.0.0.1:123`. You can listen on all available network interfaces at once
    using `0.0.0.0:123` for IPv4 or `[::]:123` for IPv6.

`rate-limiting-cache-size` = *size* (**0**)
:   Number of elements in the rate limiting cache. At most *size* elements are
    kept in the cache. This means that if more than *size* different clients
    attempt to connect to the server too frequently, the cache size will have
    reduced functionality, as rate limiting information gets lost when new
    clients connect to the server. If set to zero, the cache is unused, this
    is the default.

`rate-limiting-cutoff-ms` = *cutoff* (**0**)
:   Minimum time between two requests from the same client, if a request was
    sent sooner than the cutoff time, the client will be asked to slow down
    their requests by the server responding with a packet with the NTP `RATE`
    kiss code. No actual time measurement will be returned to the client in
    that case. If set to zero, no rate limiting is applied, this is the default.

`allowlist` = { filter = [ *subnet*, .. ], action = `"deny"` | `"ignore"` } (**unset**)
:   Only allow any number of filtered *subnets* to connect to the daemon. Any
    IP that matches one of the subnets specified is allowed to contact this
    server. The subnets must be specified in CIDR notation (an IP address
    followed by a slash and the number of masked bits, for example `127.0.0.1/8`
    or `192.168.1.1/24`). The action determines what measure is taken for IP
    addresses not in any of the specified subnets. When `deny`, an explicit
    packet with the NTP `DENY` kiss code is returned to the sender indicating
    that they are not allowed to do so. When `ignore` is specified, messages are
    discarded with no response sent. The default value is equivalent to allowing
    any IP address, and would be equivalent to setting the filter to
    `["0.0.0.0/0", "::/0"]`, with either action.

`denylist` = { filter = [ *subnet*, .. ], action = `"deny"` | `"ignore"` } (**unset**)
:   Do not allow any number of filtered *subnets* to connect to the daemon. Any
    IP that matches one of the subnets specified is not allowed to contact this
    server. The subnets must be specified in CIDR notation (an IP address
    followed by a slash and the number of masked bits, for example `127.0.0.1/8`
    or `192.168.1.1/24`). The action determines what measure is taken for IP
    addresses in any of the specified subnets. When `deny`, an explicit packet
    with the NTP `DENY` kiss code is returned to the sender indicating that they
    are not allowed to do so. When `ignore` is specified, messages are discarded
    with no response sent. The default value is equivalent to allowing any IP
    address, and would be equivalent to setting the filter to `[]`, with either
    action.

`require-nts` = `true` | `false` | `"deny"` | `"ignore"` (**false**)
:   Whether incoming requests to the server must have NTS enabled. When set to
    `true` or `"ignore"` any non-NTS enabled messages will be ignored. When set
    to `"deny"` non-NTS enabled messages will be explicitly denied with an NTP
    `DENY` kiss code. When set to `false` (the default), normal NTP messages are
    also allowed.

## `[observability]`
Settings in this section configure how you can observe the behavior of the
daemon. Currently the daemon can be observed either through the logs or by
retrieving several key metrics either through ntp-ctl(8) or through
ntp-metrics-exporter(8).

`log-level` = `"trace"` | `"debug"` | `"info"` | `"warn"` | `"error"` (**unset**)
:   Set the logging level for messages printed to stdout. The lowest level
    `trace` gives very detailed information about anything going on in the
    daemon, whereas the highest level `error` only logs error conditions in the
    daemon. Levels higher than the given log level are logged as well. If not
    set (the default), then logging will be completely disabled.

`observation-path` = *path* (**unset**)
:   Path where the daemon will create an observation unix domain socket. This
    socket is used by `ntp-ctl` and `ntp-metrics-exporter` to read the current
    status of the daemon. If not set (the default) no observation socket will be
    created and it is not possible to use `ntp-ctl` or `ntp-metrics-exporter` to
    observe the daemon.

`observation-permissions` = *mode* (**0o666**)
:   The file system permissions with which the observation socket should be
    created. Warning: You should always write this number with the octal prefix
    `0o`, otherwise your permissions might be interpreted wrongly. The default
    should be ok for most applications however.

`metrics-exporter-listen` = *socketaddr* (**127.0.0.1:9975**)
:   The listen address that is used for the ntp-metrics-exporter(8).

## `[keyset]`
The keyset configures the internal key infrastructure for NTS packets. Note that
this is separate from the TLS certificate and private key, for those see the
relevant configuration in the `[[nts-ke-server]]` section.

`stale-key-count` = *count* (**7**)
:   Maximum number of old keys to retain in the cache. Whenever keys are rotated
    the old keys will become invalid, but clients may still have NTS cookies
    encrypted with any of the old keys.

`key-rotation-interval` = *seconds* (**86400**)
:   Time between key rotation events. Every time *seconds* elapses, a new
    internal key will be generated for creating NTS cookies. By default this is
    set to a day.

`key-storage-path` = *path* (**unset**)
:   If set, stores the internal NTS keys in the file indicated by *path*. This
    allows keys to survive a server reboot. If not set, clients using NTS may
    need to redo a key exchange operation to get new NTS cookies.
    The daemon will not create any parent directories if they don't exist.
    It will create the file if it doesn't exist.


## `[[nts-ke-server]]`
The daemon can be configured to operate as an NTS key exchange server by
repeating any number of `[[nts-ke-server]]` sections. If no such sections have
been defined, the daemon will offer no NTS key exchange services. All NTS-KE
servers make use of the shared keyset. It is the purpose of the key exchange
server to distribute cookies to clients in a safe way. These cookies can then
be used in NTP packets with the normal server to validate that the traffic was
untampered with.

`listen` = *socket*
:   Address of a TCP socket on which the server should listen for incoming NTS
    key exchange requests. Specified as an interface IP address, a colon and a
    port number. The standard port number for an NTS key exchange server is TCP
    port 4460. Both IPv4 and IPv6 are supported. For example to listen on
    localhost port 4460 in IPv4 you can use `127.0.0.1:4460`. You can listen on
    all available network interfaces at once using `0.0.0.0:4460` for IPv4 or
    `[::]:4460` for IPv6.

`certificate-chain-path` = *path*
:   Path to a certificate chain for the public certificate that the server
    offers to clients.

`private-key-path` = *path*
:   Path to the private key associated with the server certificate in the
    certificate chain.

`key-exchange-timeout-ms` = *timeout* (**1000**)
:   Timeout in milliseconds for how long a key exchange may take. If the timeout
    is exceeded the connection will be dropped.

`concurrent-connections` = *number* (**512**)
:   Maximum number of concurrent connections the key exchange server will handle.
    Any connections above the threshold will be held in an OS level queue.

`ntp-port` = *port*
    Port number the key exchange server should instruct clients to use. Should
    be used when the port number of the NTP server is not the default.

`ntp-server` = *server-name*
    Server address (either as ip or as domain name) where clients can find the
    NTP server. Should be used when this name does not match the name of the
    NTS key exchange server.

## `[synchronization]`
This section of the configuration focusses on how the time information from the
time sources is gathered and applied to the system clock.

`minimum-agreeing-sources` = *count* (**3**)
:   The minimum number of sources that should agree on the current time before
    the daemon does any steering operation on the clock. Note that if you have
    configured fewer than this amount of sources, this may result in the daemon
    never updating the clock.

`single-step-panic-threshold` = *seconds* | { `forward` = *forward*, `backward` = *backward* } (**1000**)
:   The threshold in seconds at which the daemon will completely exit (i.e.
    panic) when a single non-startup step occurs. Generally during normal
    operation the clock on your system should run somewhat close to the time it
    is synchronized to. As such, it is highly unlikely that such a large step
    will take place, and the daemon will exit to prevent any accidental
    mistakes. If set to the value `"inf"`, any step will be allowed. May either
    be configured as one number of seconds for both forward and backward steps,
    or separate values for forward and backward steps.

`startup-step-panic-threshold` = *seconds* | { `forward` = *forward*, `backward` = *backward* } (**{ forward = "inf", backward = "86400" }**)
:   The threshold in seconds at which the daemon will completely exit (i.e.
    panic) when a step occurs at startup. The default allows any forward step,
    but prevents backward steps larger than a single day. Generally computer
    clocks that are not synchronized will run behind the true time, instead of
    running ahead. If a computer is running ahead and steps back a large time
    this generally indicates a problem. If set to the value `"inf"`, any step
    will be allowed. May either be configured as one number of seconds for both
    forward and backward steps, or separate values for forward and backward
    steps.

`accumulated-step-panic-threshold` = *seconds* (**unset**)
:   Every time the daemon steps the time instead of slowly adjusting the clock
    by using frequency changes, this counter is increased by the absolute value
    of the step (i.e. both forward and backward steps are counted). When this
    threshold is reached, the daemon will exit immediately (i.e. panic). During
    normal operation steps are unlikely to occur, and as such, steps may
    indicate that someone or something is triggering illicit steps. By default
    however this panic mechanism is disabled. Is disabled if left unset or if
    set to the value `0`.

`local-stratum` = *stratum* (**16**)
:   Sets the NTP clock stratum of the system clock when no NTP time sources have
    been configured, or when the time has not yet been synchronized from an NTP
    time source. Can be used in servers to indicate that there are external
    mechanisms synchronizing the clock.

## `[synchronization.algorithm]`
Warning: the algorithm section contains mostly internal algorithm tweaks that
generally do not need to be changed. However, they are offered here for specific
use cases. These settings are considered implementation details however, and as
such may change in future ntpd-rs versions.

`precision-low-probability` = *probability* (**1/3**)
:   Probability bound below which we start moving towards decreasing our
    precision estimate. Unit: probability, 0-1

`precision-high-probability` = *probability* (**2/3**)
:   Probability bound above which we start moving towards increasing our
    precision estimate. Unit: probability, 0-1

`precision-hysteresis` = *hysteresis* (**16**)
:   Amount of hysteresis in changing the precision estimate. Unit: count, 1+

`precision-minimum-weight` = *weight* (**0.1**)
:   Lower bound on the amount of effect our precision estimate has on the total
    noise estimate before we allow decreasing of the precision estimate. Unit:
    weight, 0-1

`poll-interval-low-weight` = *weight* (**0.4**)
:   Amount which a measurement contributes to the state, below which we start
    increasing the poll interval. Unit: weight, 0-1

`poll-interval-high-weight` = *weight* (**0.6**)
:   Amount which a measurement contributes to the state, above which we start
    decreasing the poll-interval interval. Unit: weight, 0-1

`poll-interval-hysteresis` = *hysteresis* (**16**)
:   Amount of hysteresis in changing the poll interval. Unit: count, 1+

`poll-interval-step-threshold` = *threshold* (**1e-6**)
:   Probability threshold for when a measurement is considered a significant
    enough outlier that we decide something weird is going on and we need to do
    more measurements. Unit: probability, 0-1

`delay-outlier-threshold` = *threshold* (**5.0**)
:   Threshold (in number of standard deviations) above which measurements with a
    significantly larger network delay are rejected. Unit: standard deviations,
    0+

`initial-wander` = *wander* (**1e-8**)
:   Initial estimate of the clock wander of the combination of our local clock
    and that of the source. Unit: s/s^2

`initial-frequency-uncertainty` = *uncertainty* (**100e-6**)
:   Initial uncertainty of the frequency difference between our clock and that
    of the source. Unit: s/s

`maximum-source-uncertainty` = *uncertainty* (**0.25**)
:   Maximum source uncertainty before we start disregarding it. Note that this
    is combined uncertainty due to noise and possible assymetry error (see also
    weights below). Unit: seconds

`range-statistical-weight` = *weight* (**2.0**)
:   Weight of statistical uncertainty when constructing overlap ranges. Unit:
    standard deviations, 0+

`range-delay-weight` = *weight* (**0.25**)
:   Weight of delay uncertainty when constructing overlap ranges. Unit: weight,
    0-1

`steer-offset-threshold` = *threshold* (**2.0**)
:   How far from 0 (in multiples of the uncertainty) should the offset be before
    we correct. Unit: standard deviations, 0+

`steer-offset-leftover` = *stddev* (**1.0**)
:   How many standard deviations do we leave after offset correction? Unit:
    standard deviations, 0+

`steer-frequency-threshold` = *threshold* (**0.0**)
:   How far from 0 (in multiples of the uncertainty) should the frequency
    estimate be before we correct. Unit: standard deviations, 0+

`steer-frequency-leftover` = *stddev* (**0.0**)
:   How many standard deviations do we leave after frequency correction? Unit:
    standard deviations, 0+

`step-threshold` = *threshold* (**0.010**)
:   From what offset should we step the clock instead of trying to adjust
    gradually? Unit: seconds, 0+

`slew-maximum-frequency-offset` = *offset* (**200e-6**)
:   What is the maximum frequency offset during a slew. Unit: s/s

`slew-minimum-duration` = *duration* (**8.0**)
:   What is the minimum duration of a slew. Unit: seconds

`maximum-frequency-steer` = *frequency* (**495e-6**)
:   Absolute maximum frequency correction. Unit: s/s

`ignore-server-dispersion` = *bool* (**false**)
:   Ignore a servers advertised dispersion when synchronizing. Can improve
    synchronization quality with servers reporting overly conservative root
    dispersion.

`meddling-threshold` = *threshold* (**5.0**)
:   Threshold for detecting external clock meddling. Unit: seconds

# SEE ALSO

[ntp-daemon(8)](ntp-daemon.8.md), [ntp-ctl(8)](ntp-ctl.8.md),
[ntp-metrics-exporter(8)](ntp-metrics-exporter.8.md)
