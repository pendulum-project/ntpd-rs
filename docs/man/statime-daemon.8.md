<!-- ---
title: STATIME-DAEMON(8) ntpd-rs 2.0.0-alpha.20261113 | ntpd-rs
--- -->

# NAME

`statime-daemon` - ntpd-rs Network Time Protocol service daemon

# SYNOPSIS

`statime-daemon` [`-c` *path*] [`-l` *loglevel*] \
`statime-daemon` `-h` \
`statime-daemon` `-v`

# DESCRIPTION

`statime-daemon` is the Network Time Protocol (NTP) service daemon for ntpd-rs, an
NTP implementation with a focus on security and stability. The `statime-daemon` can
be configured as both an NTP client and an NTP server. The daemon also works
with the Network Time Security (NTS) protocol. Details of the configuration
of the daemon and implementation details can be found in ntp.toml(5), where
several concepts of the statime-daemon are also explained.

# OPTIONS

`-c` *path*, `--config`=*path*
:   The configuration file path for the statime-daemon where settings for the
    configuration of ntpd-rs are stored. If not specified the default
    configuration file is `/etc/ntpd-rs/ntp.toml`.

`-h`, `--help`
:   Display usage instructions.

`-l` *loglevel*, `--log-level`=*loglevel*
:   Change which log messages are logged to stdout. Available log levels are
    *trace*, *debug*, *info*, *warn* and *error* (from lower to higher
    priority). Only messages with the given priority and higher will be
    displayed. The default log level is *info*.

`-v`, `--version`
:   Display version information.

# SEE ALSO

[statime(8)](statime.8.md),
[statime-metrics(8)](statime-metrics.8.md),
[ntp.toml(5)](ntp.toml.5.md)
