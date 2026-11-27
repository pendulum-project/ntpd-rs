<!-- ---
title: NTP.TOML(5) ntpd-rs 2.0.0-alpha.20261113 | ntpd-rs
--- -->

# NAME

`ntp.toml` - configuration file for the ntpd-rs statime-daemon

# DESCRIPTION

The configuration of the ntpd-rs daemon is controlled through a number of TOML
configuration files. The primary configuration file is loaded from
`/etc/ntpd-rs/ntp.toml`, unless otherwise specified on the command line when
starting the daemon. It can specify a folder containing further configuration
files, which are used to provide defaults for settings not present in the
primary configuration file.

The TOML file format is in lots of ways similar to a simple INI with several
extensions allowing a JSON-like syntax. For the simplest cases, each setting is
placed on its own line, with the name of the setting on the left hand sign of
an equals sign, and the value on the right hand side. String values are quoted,
whilst numbers and boolean values like true/false are placed without any
quotes. This document will provide example values for all settings. A full
specification of the syntax of toml files can be found at [toml.io](https://toml.io).

The ntpd-rs configuration is split up into several sections. Each of these
sections controls a separate aspect of the daemons operations. Most settings
have defaults, which are shown in brackets as (**emphasized**). This document
organizes all settings by section.

# EXPERIMENTAL FEATURES

The ntpd-rs daemon supports a number of features which are experimental. Such
features may change between versions in ways which are backwards incompatible.
Settings related to such features will be marked in this documentation. Note
that a configuration using such settings may not work with future versions
of ntpd-rs.

# SPECIFICATION OF DURATIONS

Various configuration settings of the daemon set some kind of duration or time
interval. These settings are specified as a human readable duration consisting
of a string with an amount and then a unit, such as `"1.2s"`. The supported
units for durations are nanoseconds (`ns`), microseconds (`us`),
milliseconds (`ms`), seconds (`s`), minutes (`m`), hours (`h`), days (`d`),
and weeks (`w`).

# CONFIGURATION

There are two settings in the daemon which change its global behavior:

`use-system-config` = *bool or path* (**false**)
:   Whether and where to fetch the system defaults. If specified as `true`, the
    system defaults are loaded from /usr/lib/ntpd-rs/system-config. The
    configuration files in the system config folder need to be disjunct, i.e. a
    setting can be specified in at most one file. In particular, this also
    holds for sources and servers, in that there can be only one file
    specifying sources, and only one file specifying servers.

`seccomp` = *mode* (**"off"**)
:   This setting is linux-specific. Enables or disables the seccomp filter. Can
    be set to `"off"`, `"log"`, or `"kill"`. In log mode, seccomp violations
    are only logged, but not acted upon. Note that the filter is experimental
    and may change in backwards incompatible ways. It also may miss system
    calls required by your specific libc. Please test with logging before
    applying the filter in a stricter mode.

## `[observability]`
Settings in this section configure how you can observe the behavior of the
daemon. Currently, the daemon can be observed either through the logs or by
retrieving several key metrics either through statime(8) or through
ntp-metrics-exporter(8).

`log-level` = `"trace"` | `"debug"` | `"info"` | `"warn"` | `"error"` (**info**)
:   Set the logging level for messages printed to stdout. The lowest level
    `trace` gives very detailed information about anything going on in the
    daemon, whereas the highest level `error` only logs error conditions in the
    daemon. Levels higher than the given log level are logged as well.

`log-path` = *path* (**unset**)
:   Path to which the daemon should direct its log output. The file at this
    location is reopened on SIGHUP. When not present, log output will be
    directed to stdout.

`log-path-metrics-exporter` = *path* (**unset**)
:   Path to which the metrics exporter daemon should direct its log output. The
    file at this location is reopened on SIGHUP. When not present, log output
    will be directed to stdout.

`ansi-colors` = `true` | `false` (see note)
:   Can be used to control ANSI escape codes in logs. By default, ANSI escape
    codes are used to add some colors and other formatting to the logs when the
    log target is a terminal.

`observation-path` = *path* (**unset**)
:   Path where the daemon will create an observation Unix domain socket. This
    socket is used by `statime` and `ntp-metrics-exporter` to read the current
    status of the daemon. If not set (the default) no observation socket will be
    created and it is not possible to use `statime` or `ntp-metrics-exporter` to
    observe the daemon.

`observation-permissions` = *mode* (**0o666**)
:   The file system permissions with which the observation socket should be
    created. Warning: You should always write this number with the octal prefix
    `0o`, otherwise your permissions might be interpreted wrongly. The default
    should be OK for most applications however.

`metrics-exporter-listen` = *socketaddr* (**127.0.0.1:9975**)
:   The listen address that is used for the ntp-metrics-exporter(8).

## `[[source]]`

Each `[[source]]` is a group of one or more time sources for the daemon to
retrieve time information from. Any number of sources can be configured by
repeating a `[[source]]` section (note the double brackets) for as many times
as required.

The daemon supports multiple ways of getting the time, from local sources such
as a gps receiver or a pps input, to remote sources such as an NTP or csptp
server. The following source types are currently supported:

`ntp`
:   An NTP source connects to a single remote NTP server. If the connection to
    the server is lost, attempts are made to reconnect to the source unless the
    connection was secured and the server indicated it never wanted to see the
    client again.

`ntp-pool`
:   An NTP pool source connects to several distinct NTP servers out of a pool
    of NTP servers. The pool is expected to either provide several servers
    behind the DNS name of the pool, or to provide multiple sources via NTS.
    Note that support for NTS with pool sources is still experimental. If the
    connection to the server is lost, a new server is retrieved from the pool.

`sock`
:   A sock source connects to a GPSd socket to get timing data from GPS
    receivers. Note that GPSd must be (re-)started after starting ntpd-rs for
    GPSd to connect to the socket.

`pps`
:   A PPS source connects to a Pulse Per Second device, which is by default
    assumed to send a pulse at the start of every second. As these devices only
    provide periodic data, they do not count towards `minimum-agreeing-sources`.

`csptp`
:   A CSPTP source connects to a single csptp server. If the connection to the
    server is lost, attempts are made to reconnect to the source. Note that
    CSPTP sources are still experimental, and only available on linux.


A source has the following configuration options:

`type` = *type*
:   Specify one of the source types that ntpd-rs supports: `ntp`, `ntp-pool`,
    `sock`, `pps`, or `csptp`. Note that `csptp` sources are experimental.

`nts` = *bool* (**false**)
:   Whether to secure communication with the source using NTS. Only supported
    for `ntp` and `ntp-pool` sources. Note that using NTS with `ntp-pool`
    sources is experimental.

`address` = *address*
:   The address of the time source. Only applicable to `ntp`, `ntp-pool`, and
    `csptp` sources. For non-NTS NTP sources, this should be the address of the
    NTP server. For csptp servers, this should be the address of the csptp
    server. For NTS sources, this should be the address of the NTS key exchange
    server. For pool sources, this should either be the dns name of the pool,
    or the NTS key exhchange server of the pool when using NTS with the pool.
    For NTP sources, the address may include a port number by appending a
    colon (`:`) followed by a port number. If not specified, the daemon will
    use the default port number (*4460* if the source uses NTS, *123* if it
    does not).

`path` = *path*
:   The path to the device or socket of the time source. Only applicable to
    `pps` and `sock` sources.

`count` = *number* (**4**)
:   Can only be set on `ntp-pool` sources. Specifies the maximum number of
    servers that the daemon will attempt to connect to from a pool. The daemon
    will keep retrying to get more sources from the pool when connections are
    lost, up to the maximum specified by this configuration value.

`ignore` = *ip addresses* (**[]**)
:   Can only be set on `ntp-pool` sources not using NTS. Specifies a list of IP
    addresses of servers in the pool which should not be used. For example:
    `["127.0.0.1"]`. Empty by default.

`ntp-version` = `4` | `5` | `"auto"` (**4**)
:   Which NTP version to use for this source. Can only be set on `ntp` and
    `ntp-pool` sources. By default this uses NTP version 4. You can use `5` to
    set the protocol version to the draft NTPv5 specification, but your source
    must support the same draft. To use the experimental upgrade protocol set
    the NTP version to `"auto"`. This uses a specially constructed NTPv4 packet
    to attempt an upgrade to the supported draft NTPv5 version if the source
    also supports the same draft version. NTPv5 support is currently in beta
    and can still change in a backwards incompatible way.

`minimum-poll-interval` = *duration* (see text)
:   Can only be set on `ntp` and `ntp-pool` sources. The minimum amount of time
    between two requests to the server. The value is given as a duration. The
    default value is taken from the `minimum-poll-interval` setting in
    `[ntp-source-defaults]`, which defaults to 16 seconds.  This is rounded up
    to the nearest power of 2 number of seconds.

`maximum-poll-interval` = *duration* (see text)
:   Can only be set on `ntp` and `ntp-pool` sources. The maximum amount of time
    between two requests to the server. The value is given as a duration. The
    default value is taken from the `minimum-poll-interval` setting in
    `[ntp-source-defaults]`, which defaults to 1024 seconds.  This is rounded
    down to the nearest power of 2 number of seconds. If the rounded value of
    `minimum-poll-interval` is larger than the `maximum-poll-interval`,
    `maximum-poll-interval` is taken equal to `minimum-poll-interval` instead.

`desired-error` = *duration* (see text)
:   The accuracy of synchronization desired from this source. The actual poll
    interval is adapted between the limits specified in `minimum-poll-interval`
    and `maximum-poll-interval` such that the clock has this much uncertainty
    if only synchronized from this source. The default is taken from the
    `desired-error` setting in `[ntp-source-defaults]`, which defaults to 1
    millisecond.

`additional-certificates` = *path* (optional)
:   Can only be set on sources using NTS. Optional path to a certificate set
    for additional certicate authorities to use, in addition to the certificate
    authorities specified by the system configuration. Note that this cannot be
    used to specify a self-signed certificate.

`precision` = *duration*
:   `pps` and `sock` sources only. Precision of the source. This should be an
    estimate of the size of the expected measurement noise. Technically defined
    as the 1-standard deviation bound on the measurement error. This is needed
    as `sock` and `pps` sources don't have a good way to estimate their own
    error.

`accuracy` = *duration* (**"0s"**)
:   `pps` and `sock` sources only. Accuracy of the underlying time source. This
    should be an estimate of the size of the error in the clock you are
    synchronizing with, as well as any mostly-unchanging offset in the
    measurement process. This can be used to deprioritize sources which have
    large offsets in the measurement process or which are of poorer quality
    than others.

`period` = *duration* (**"1s"**)
:   Only for `pps` sources. Period of the pulse signal. The time signal is
    assumed to arive on integer multiples of the period, starting at the
        (virtual) TAI epoch of midnight on the first of januari 1970. Note that
        this means that when using multi-second periods, these may not align
        with the minute or hour mark of the UTC timescale.

`enable-srv-resolution` = *bool* (**false**)
:   Can only be set on sources using NTS. Enables following SRV records when
    resolving the address of the NTS key exchange server. Such records must be
    DNSSEC signed. Note that this feature is experimental and may change in
    backwards incompatible ways.

`delay-decay-rate` = *rate* (see text)
:   Can only be set for `ntp`, `ntp-pool` and `csptp` sources. How quickly we
    lose confidence in the observed time delay between us and this time source.
    This setting is experimental and primarily intended for use by experts when
    fine-tuning the synchronization algorithm. The default value is taken from
    the `delay-decay-rate` setting in `[ntp-source-defaults]` for NTP sources,
    and from the `delay-decay-rate` setting in `[csptp-source-defaults]` for
    `csptp` sources, both of which defaults to `0.003402069`.

`domain` = *number* (see text)
:   Can only be set on `csptp` sources. PTP domain number to be used in
    communication with the CSPTP server. The default value is taken from the
    `domain` setting in `[csptp-source-defaults]`, which defaults to 128.

`poll-interval` = *duration* (see text)
:   Can only be set on `csptp` sources. How often to query the CSPTP server for
    the current time. The default value is taken from the `poll-interval`
    setting in `[csptp-source-defaults]`, which defaults to 1 second.

`response-interval` = *duration* (see text)
:   Can only be set on `csptp` sources. How long to wait for a reply to a
    request. Replies received after this interval will be ignored. The default
    value is taken from the `response-interval` setting in
    `[csptp-source-defaults]`, which defaults to 1 second.

## `[filter]`

Before being used to synchronize the system's time, sources are checked for
sufficient quality and against each other for consistency. These settings
control how that checking is done:

`minimum-agreeing-sources` = *number* (see text)
:   The number of sources that need to agree on the current time before the
    current system's time is modified. By default, this is the smaller of 3 and
    the number of sources configured, excluding any pulse-per-second sources.

`select-offset-uncertainty-window` = *size* (**1.0**)
:   Size of the window of uncertainty to assume around a source's offset, based
    on the observed noise in the offset. This setting is experimental and may
    change in backwards incompatible ways. It is primarily intended for experts
    trying to tune the algorithm.

`select-link-uncertainty-window` = *size* (**2.0**)
:   Size of the window of uncertainty to assume around a source's offset, based
    on the observed noise in the link delay. This setting is experimental and
    may change in backwards incompatible ways. It is primarily intended for
    experts trying to tune the algorithm.

`select-delay-uncertainty-window` = *size* (**0.5**)
:   Size of the window of uncertainty to assume around a source's offset, based
    on the potential asymmetry due to delay and root delay. This setting is
    experimental and may change in backwards incompatible ways. It is primarily
    intended for experts trying to tune the algorithm.

`select-max-window-size` = *duration* (**1s**)
:   Maximum total size of the uncertainty window of a source before we judge a
    source to be unsuitable for synchronization. This setting is experimental
    and may change in backwards incompatible ways. It is primarily intended for
    experts trying to tune the algorithm.

## `[system-clock]`

Controls for how the system clock is steered:

`steered` = *bool* (**true**)
:   Whether the system clock is actually steered. If false, the daemon keeps
    track of the deviation of the system clock from the actual time, but the
    actual system clock is not updated based on that estimate.

`startup-jump-warning-threshold` = *threshold set* (**"0s"**)
:   How large a step must be at startup to trigger a warning. Can be set to
    "inf" to disable this warning entirely. The threshold can be either
    symmetric, in which case it is specified as a duration, or asymmetric, in
    which case a separate forward and backward jump threshold can be given,
    each of which can be infinite. An example of an asymmetric threshold is
    `{ forward = "inf", backward = "0s" }`.

`startup-jump-abort-threshold` = *threshold set* (**{ forward = "inf", backward = "1d" }**)
:   How large a step must be at startup to cause us to stop trusting our
    ability to steer the clock and abort the daemon. Can be set to "inf" to
    disable aborting on jumps at startup entirely. The threshold can be either
    symmetric, in which case it is specified as a duration, or asymmetric, in
    which case a separate forward and backward jump threshold can be given,
    each of which can be infinite.

`single-jump-warning-threshold` = *threshold set* (**"0s"**)
:   How large a jump during regular operation must be to trigger a warning. Can
    be set to "inf" to disable this warning entirely. The threshold can be
    either symmetric, in which case it is specified as a duration, or
    asymmetric, in which case a separate forward and backward jump threshold
    can be given, each of which can be infinite. An example of an asymmetric
    threshold is `{ forward = "inf", backward = "0s" }`.

`single-jump-abort-threshold` = *threshold set* (**"1000s"**)
:   How large a jump must be during regular operation to cause us to stop
    trusting our ability to steer the clock and abort the daemon. Can be set to
    "inf" to disable aborting on jumps during regular operations entirely. The
    threshold can be either symmetric, in which case it is specified as a
    duration, or asymmetric, in which case a separate forward and backward jump
    threshold can be given, each of which can be infinite. An example of an
    asymmetric threshold is `{ forward = "inf", backward = "0s" }`.

`accumulated-jump-warning-threshold` = *duration* (**"inf"**)
:   How large all jumps, excluding jumps at startup, combined must be, befores
    triggering a warning. Can be used to trigger a warning before an abort is
    triggered from passing `accumulated-jump-abort-threshold`, giving the
    operator a chance to intervene before that threshold is triggered. Can be
    set to "inf" to disable this warning entirely.

`accumulated-jump-abort-threshold` = *duration* (**"inf"**)
:   How large all jumps, excluding a single jump at startup, combined must be,
    before we stop trusting our ability to steer the clock and abort the
    daemon. Can be set to "inf" to disable aborting on the total amount jumped
    entirely.

`startup-end-threshold` = *duration* (**"1s"**)
:   The uncertainty on the current time below which we consider the clock to
    have transitioned out of startup. If the clock later goes to a larger
    uncertainty again, it will still be considered out of startup. This setting
    is experimental and may change in backwards incompatible ways. It is
    primarily intended for experts trying to tune the algorithm.

`jump-threshold` = *duration* (**"10s"**)
:   How large the clock offset needs to be before we make a jump. This setting
    is experimental and may change in backwards incompatible ways. It is
    primarily intended for experts trying to tune the algorithm.

`slew-time-constant` = *duration* (**"8s"**)
:   The amount of time to spread slewing over. This gives a typical time scale
    to reduce the offset error by about two thirds using slews. This setting is
    experimental and may change in backwards incompatible ways. It is primarily
    intended for experts trying to tune the algorithm.

`synchronized-threshold` = *duration* (**"1s"**)
:   Offset and uncertainty below which we consider the clock synchronized. This
    setting is experimental and may change in backwards incompatible ways. It
    is primarily intended for experts trying to tune the algorithm.

`initial-wander` = *amount* (**1e-8**)
:   Initial estimate of how much the frequency of the clock wanders, as
    fractions of a second per second. This setting is experimental and may
    change in backwards incompatible ways. It is primarily intended for experts
    trying to tune the algorithm.

## `[ntp-source-defaults]`

Some of the behavior of NTP sources is configurable. The defaults for these
settings can be set here:

`minimum-poll-interval` = *duration* (**"16s"**)
:   The minimum amount of time between two requests to the NTP server. The
    value is given as a duration. This is rounded up to the nearest power of 2
    number of seconds.

`maximum-poll-interval` = *duration* (**"1024s"**)
:   The maximum amount of time between two requests to the NTP server. The
    value is given as a duration. This is rounded down to the nearest power of
    2 number of seconds. If the rounded value of `minimum-poll-interval` is
    larger than the `maximum-poll-interval`, `maximum-poll-interval` is taken
    equal to `minimum-poll-interval` instead.

`desired-error` = *duration* (**"1ms"**)
:   The accuracy of synchronization desired from NTP sources. The actual poll
    interval is adapted between the limits specified in `minimum-poll-interval`
    and `maximum-poll-interval` such that the clock has this much uncertainty
    if only synchronized from this source.

`delay-decay-rate` = *rate* (**0.003402069**)
:   How quickly we lose confidence in the observed time delay between us and
    NTP time sources. This setting is experimental and primarily intended for
    use by experts when fine-tuning the synchronization algorithm.

## `[csptp-source-defaults]`

Some of the behaviour of csptp sources is configurable. The defaults for these
settings can be set here. Note that csptp sources are still experimental, and
may change in backwards incompatible ways in future versions.

`domain` = *number* (**128**)
:   PTP domain number to be used in communication with CSPTP servers.

`poll-interval` = *duration* (**"1s"**)
:   How often to query the CSPTP server for the current time.

`response-interval` = *duration* (**"1s"**)
:   How long to wait for a reply to a request. Replies received after this
    interval will be ignored.

`delay-decay-rate` = *rate* (**0.003402069**)
:   How quickly we lose confidence in the observed time delay between us and
    csptp time sources. This setting is experimental and primarily intended for
    use by experts when fine-tuning the synchronization algorithm.

## `[[server]]`

The daemon can be configured to act as a server for various protocol via one or
more `[[server]]` sections. If no such sections have been defined, the daemon
runs in a client only mode. Each server listens on a specific socket address
and port, for a specific protocol. The following server types are currently
supported:

`ntp`
:   A server providing time to clients via the NTP protocol, optionally
    protected with NTS. Can be configured to support versions 3, 4, and drafts
    of version 5. Note that support for NTP version 5 drafts is experimental
    and may change in backwards incompatible ways.

`ntske`
:   A server handling NTS key exchange requests for clients, providing the
    initial setup needed for protecting NTP exchanges with NTS.

`csptp`
:   A server providing time to clients via a draft version of the csptp
    protocol. Note that support for csptp is experimental and may change in
    backwards incompatible ways.

A source has the following configuration options:

`type` = *server type*
:   Specify one of the server types ntpd-rs supports. Must be one of `ntp`,
    `ntske`, or `csptp`. Note that `csptp` servers are experimental and may
    change in backwards incompatible ways.

`listen` = *socket address*
:   Address of the socket on which the server should listen for incoming
    requests. Is interpreted as a UDP socket address for `ntp` servers, and as
    a TCP socket address for `ntske` servers. Cannot be specified for `csptp`
    servers. Specified as an interface IP address, a colon, and a port number.
    When the port number is not specified, UDP port 123 will be used for `ntp`
    servers, and TCP port 4460 will be used for `ntske` servers. Both IPv4 and
    IPv6 are supported. It is possible to listen on all addresses associated
    with the local machine using `0.0.0.0:123` for IPv4, or `[::]:123` for
    IPv6.

`accept-ntp-version` = *list of NTP versions* (see text)
:   A list of NTP versions this server should support. Cannot be specified for
    `csptp` servers. By default, `ntp` servers will support NTP versions 3 and
    4 (corresponding to the configuration value`[3, 4]`), whilst `ntske`
    servers will only support NTP version 4. `ntske` servers cannot support NTP
    version 3 as NTS requires NTP version 4 or later. Support for a draft of
    NTP version 5 can be enabled by including 5 in the list of accepted NTP
    versions. Note that NTP version 5 support is experimental and may change in
    backwards incompatible ways.

`require-nts` = *bool or response action* (**false**)
:   For `ntp` servers only. Whether to only respond to NTS secured NTP packets.
    When set to true, incoming NTP packets that are not authenticated are
    silently ignored. Can also be set to `deny` to respond with a NTP packet
    indicating the client is not welcome, or to `ignore` to explicitly ignore
    non-NTS NTP packets.

`allowlist` = { ranges = [ *subnet*, .. ], action = `"deny"` | `"ignore"` } (**unset**)
:   For `ntp` servers only. Only allow any number of filtered *subnets* to
    connect to the server. Any IP that matches one of the subnets specified is
    allowed to contact this server. The subnets must be specified in CIDR
    notation (an IP address followed by a slash and the number of masked bits,
    for example `127.0.0.1/8` or `192.168.1.1/24`). The action determines what
    measure is taken for IP addresses not in any of the specified subnets. When
    `deny`, an explicit packet with the NTP `DENY` kiss code is returned to the
    sender indicating that they are not allowed to do so. When `ignore` is
    specified, messages are discarded with no response sent. The default value
    is equivalent to allowing any IP address, and would be equivalent to
    setting the filter to `["0.0.0.0/0", "::/0"]`, with either action.

`denylist` = { ranges = [ *subnet*, .. ], action = `"deny"` | `"ignore"` } (**unset**)
:   For `ntp` servers only. Do not allow any number of filtered *subnets* to
    connect to the daemon. Any IP that matches one of the subnets specified is
    not allowed to contact this server. The subnets must be specified in CIDR
    notation (an IP address followed by a slash and the number of masked bits,
    for example `127.0.0.1/8` or `192.168.1.1/24`). The action determines what
    measure is taken for IP addresses in any of the specified subnets. When
    `deny`, an explicit packet with the NTP `DENY` kiss code is returned to the
    sender indicating that they are not allowed to do so. When `ignore` is
    specified, messages are discarded with no response sent. The default value
    is equivalent to allowing any IP address, and would be equivalent to
    setting the filter to `[]`, with either action.

`rate-limiting-cache-size` = *size* (**0**)
:   For `ntp` servers only. Number of elements in the rate limiting cache. At
    most *size* elements are kept in the cache. This means that if more than
    *size* different clients attempt to connect to the server too frequently,
    the cache will have reduced functionality, as rate limiting information
    gets lost when new clients connect to the server. If set to zero, the cache
    is unused and rate limiting is disabled, this is the default.

`rate-limiting-cutoff-ms` = *cutoff* (**0**)
:   For `ntp` servers only. Minimum time between two requests from the same
    client, if a request was sent sooner than the cutoff time, the client will
    be asked to slow down their requests by the server responding with a packet
    with the NTP `RATE` kiss code. No actual time measurement will be returned
    to the client in that case. If set to zero, no rate limiting is applied,
    this is the default.

`certificate-chain` = *path*
:   For `ntske` servers only. Path to a certificate chain for the public
    certificate that the server offers to clients.

`private-key` = *path*
:   For `ntske` servers only. Path to the private key associated with the
    server certificate in the certificate chain.

`ntp-port` = *port*
    For `ntske` servers only. Port number the key exchange server should
    instruct clients to use. Should be used when the port number of the NTP
    server is not the default.

`ntp-server` = *server-name*
    For `ntske` servers only. Server address (either as ip or as domain name)
    where clients can find the NTP server. Should be used when this name does
    not match the name of the NTS key exchange server.

`key-exchange-timeout-ms` = *timeout* (**1000**)
:   For `ntske` servers only. Timeout in milliseconds for how long a key
    exchange may take. If the timeout is exceeded the connection will be
    dropped.

`concurrent-connections` = *number* (**512**)
:   For `ntske` servers only. Maximum number of total concurrent connections
    the key exchange server will handle. Any connections above the threshold
    will be held in an OS level queue.

`network-wait-period` = *duration* (**"1s"**)
:   For `ntp` and `ntske` servers only. How long to wait before trying to
    reopen the network socket should the network socket fail in some way. This
    setting is experimental and its implementation may change in backwards
    incompatible ways.

`accepted-pool-authentication-tokens` = *list of keys* (**[]**)
:   Tokens pools can use to authenticate pool-specific requests to this NTS
    server. Note that pool support is currently in beta and can still change in
    a backwards incompatible way.

`longlived-connections` = *number* (**`concurrent-connections`/10**)
:   For `ntske` servers only. Maximum number of concurrent longlived
    connections from NTS pools the key exchange server will handle. Note that
    pool support is currently in beta and can still change in backwards
    incompatible ways.

`protocol` = *transport protocol*
:   For `csptp` servers only. Which transport protocol to use for the csptp
    messages. Can be either `"udpv4"`, for udp transport over ipv4, or
    `"udpv6"`, for udp transport of ipv6. Note that `csptp` support is
    experimental and cna still change in backwards incompatible ways.

## `[nts-cookie-keys]`

In NTS secured NTP traffic, the client communicates to the server which keys to
use through a cookie which it received from the server at an earlier time. In
ntpd-rs, these cookies contain encrypted versions of the NTS keys. The settings
here control the generation and storage of these keys when acting as an NTP
secured NTS server or NTS key exchange server.

`old-key-count` = *count* (**7**)
:   Maximum number of old keys to keep around. Whenever keys are rotated the
    old keys will stop being used to generate new cookies, but clients may
    still have NTS cookies encrypted with any of the old keys.

`key-rotation-interval` = *duration* (**"1d"**)
:   Time between key rotation events. Every time *duration* elapses, a new
    internal key will be generated for creating NTS cookies. By default this is
    set to a day.

`storage-path` = *path* (**unset**)
:   If set, stores the internal NTS keys in the file indicated by *path*. This
    allows keys to survive a server reboot. If not set, clients using NTS may
    need to redo a key exchange operation to get new NTS cookies. The daemon
    will not create any parent directories if they don't exist. The daemon will
    create the file if it doesn't exist.

## `[csptp]`

CSPTP servers provide some information to their clients about where the time
they provide comes from. The settings in this section provide the values used
for this when the server isn't synchronizing itself to another CSPTP time
source. Note that CSPTP support is based on a draft and still experimental, so
these settings may change in backwards incompatible ways.

`identity` = *clock identity* (**[0, 0, 0, 0, 0, 0, 0, 0]**)
:   The identity advertised to remote clocks when we are not synchronized to
    another CSPTP time source.

`priority-1` = *number* (**255**)
:   The value of priority-1 advertised to remote clocks when we are not
    synchronized to another CSPTP time source.

`priority-2` = *number* (**255**)
:   The value of priority-2 advertised to remote clocks when we are not
    synchronized to another CSPTP time source.

`clock-class` = *number* (**248**)
:   The clock class advertised to remote clocks when we are not synchronized to
    another CSPTP time source. For the meaning of this value, see table 4 in
    IEEE Std. 1588-2019.

`advertised-clock-accuracy` = *duration* (**unset**)
:   The accuracy of our clock advertised to remote clocks when we are not
    synchronized to another CSPTP time source. When not set, the accuracy is
    advertised as unknown.

`advertised-clock-precision` = *duration* (**"300us"**)
:   The precision of our clock advertised to remote clocks when we are not
    synchronized to another CSPTP time source.

`ptp-timescale` = *bool* (**true**)
:   Whether we use the ptp timescale for the local clock. If false, this
    implies an arbitrary timescale.

`time-traceable` = *bool* (**false**)
:   Whether our local time is traceable to a valid standard reference when we
    are not synchronized to another CSPTP time source.

`frequency-traceable` = *bool* (**false**)
:   Whether our local clock frequency is traceable to a valid standard
    reference when we are not synchronized to another CSPTP time source.

# SEE ALSO

[statime-daemon(8)](statime-daemon.8.md), [statime(8)](statime.8.md),
[ntp-metrics-exporter(8)](ntp-metrics-exporter.8.md)
