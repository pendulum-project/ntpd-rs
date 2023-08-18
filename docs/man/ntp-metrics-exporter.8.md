<!-- ---
title: NTP-METRICS-EXPORTER(8) ntpd-rs 0.3.6 | ntpd-rs
--- -->

# NAME

`ntp-metrics-exporter` - Prometheus/OpenMetrics exporter for the ntpd-rs daemon

# SYNOPSIS

`ntp-metrics-exporter` [`-c` *path*] [`-o` *path*] [`-l` *socketaddr*] \
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

`-l` *socketaddr*, `--listen-socket`=*socketaddr*
:   Specify the socket address on which the prometheus exporter should listen
    for incoming connections. The socket address should be specified as a
    combination of an interface IP address and port, separated by a colon. This
    defaults to `localhost:9975` if not specified.

`-o` *path*, `--observation-socket`=*path*
:   Direct path to the observation unix socket where the exporter can connect to
    the ntp-daemon. If not specified the observation socket path is retrieved
    from the configuration file.

`-v`, `--version`
:   Display version information.

# SEE ALSO

[ntp-daemon(8)](ntp-daemon.8.md), [ntp-ctl(8)](ntp-ctl.8.md),
[ntp.toml(5)](ntp.toml.5.md)
