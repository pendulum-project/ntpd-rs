<!-- ---
title: NTP-METRICS-EXPORTER(8) ntpd-rs 1.3.0 | ntpd-rs
--- -->

# NAME

`ntp-metrics-exporter` - Prometheus/OpenMetrics exporter for the ntpd-rs daemon

# SYNOPSIS

`ntp-metrics-exporter` [`-c` *path*] \
`ntp-metrics-exporter` `-h` \
`ntp-metrics-exporter` `-v`

# DESCRIPTION

Exports the status metrics from the ntpd-rs daemon as Prometheus/OpenMetrics
via an HTTP socket.

# OPTIONS

`-c` *path*, `--config`=*path*
:   Path to the configuration file where the observation socket path for
    connecting with the ntp-daemon is specified. This defaults to
    `/etc/ntpd-rs/ntp.toml` if not specified.

`-h`, `--help`
:   Display usage instructions.

`-v`, `--version`
:   Display version information.

# SEE ALSO

[ntp-daemon(8)](ntp-daemon.8.md), [ntp-ctl(8)](ntp-ctl.8.md),
[ntp.toml(5)](ntp.toml.5.md)
