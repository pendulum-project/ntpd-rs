<!-- ---
title: STATIME-METRICS(8) ntpd-rs 2.0.0-alpha.20261113 | ntpd-rs
--- -->

# NAME

`statime-metrics` - Prometheus/OpenMetrics exporter for the ntpd-rs daemon

# SYNOPSIS

`statime-metrics` [`-c` *path*] \
`statime-metrics` `-h` \
`statime-metrics` `-v`

# DESCRIPTION

Exports the status metrics from the ntpd-rs daemon as Prometheus/OpenMetrics
via an HTTP socket.

# OPTIONS

`-c` *path*, `--config`=*path*
:   Path to the configuration file where the observation socket path for
    connecting with the statime-daemon is specified. This defaults to
    `/etc/ntpd-rs/ntp.toml` if not specified.

`-h`, `--help`
:   Display usage instructions.

`-v`, `--version`
:   Display version information.

# SEE ALSO

[statime-daemon(8)](statime-daemon.8.md), [statime(8)](statime.8.md),
[ntp.toml(5)](ntp.toml.5.md)
