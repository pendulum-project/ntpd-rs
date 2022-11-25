# Management Client

ntpd-rs comes with a management client for the daemon. This client can show the current state of the daemon, as well as change the log level and panic thresholds of the daemon.

## Enabling the management client

In order to communicate with the daemon, the management client relies on two sockets, an observation socket and a configuration socket, which are disabled by default. To enable use of the client, these sockets should be enabled in [the configuration](CONFIGURATION.md). On Linux, it is common to place these sockets in a subdirectory of `/run` specific to the daemon.

The client can run with only one of the sockets enabled. In that situation, not all functionality is available. The same holds when the currently running user has insufficient permissions for one of the sockets.

For the configuration socket, default permissions restrict access to the group under which the server is running. Users should be added to this group when they need to be able to change configuration settings of the daemon dynamically.

## Using the management client

The current client exposes 3 different commands:
 - `ntp-ctl peers` displays information on the currently active peer connections
 - `ntp-ctl system` displays information on the current synchronization state of the system.
 - `ntp-ctl prometheus` combines output of `ntp-ctl peers` and `ntp-ctl system` in the
   prometheus export format
 - `ntp-ctl config` allows changing of some configuration parameters

## Available configuration parameters

Currently, only the `log-level` and `panic-threshold` configuration parameters can be set dynamically, through the `--log-level` and `--panic-threshold` command line parameters respectively. For information on the allowed values for these, see [the configuration documentation](CONFIGURATION.md). Note that for the panic threshold, only symmetric thresholds can be configured through the management client.

## Specifying socket locations

By default, the management client looks for the daemons configuration either in `./ntp.toml` or `/etc/ntp.toml` in order to extract the paths of the socket. If neither of these are present, or when the socket paths are not configured in these, it defaults to `/run/ntpd-rs/observe` for the observation socket and `/run/ntpd-rs/configure` for the configuration sockets.

If the client fails to find the correct socket paths using the above process, it can be manually configured to look elsewhere. Most advisable is to point the management client to the configuration file of the server via the `--config` command line flag. If this is not an option in your setup, alternatively the `--observation-socket` and `--configuration-socket` command line options.

## Output format

Output is given as formatted json

**peer:**
```
[
  {
    "Observable": {
      "statistics": {
        "offset": -0.0005991163199299752,
        "delay": 0.011262269460424378,
        "dispersion": 7.93750205494871,
        "jitter": 3.814697266513178e-6
      },
      "reachability": 1,
      "uptime": {
        "secs": 11,
        "nanos": 132546117
      },
      "poll_interval": {
        "secs": 16,
        "nanos": 0
      },
      "peer_id": 1566498883
    }
  },
  {
    "Observable": {
      "statistics": {
        "offset": 0.0019689977639282584,
        "delay": 0.014038344615613657,
        "dispersion": 7.937502046101145,
        "jitter": 3.814697266513178e-6
      },
      "reachability": 1,
      "uptime": {
        "secs": 11,
        "nanos": 127481359
      },
      "poll_interval": {
        "secs": 16,
        "nanos": 0
      },
      "peer_id": 2928306951
    }
  }
]
```

**client:**
```
{
  "poll_interval": 4,
  "precision": 3.814697266513178e-6,
  "leap_indicator": "NoWarning",
  "accumulated_steps": 0.005327121588710491,
  "accumulated_steps_threshold": null
}
```

**prometheus**

```
# HELP ntp_system_poll_interval_seconds Time between polls of the system.
# TYPE ntp_system_poll_interval_seconds gauge
# UNIT ntp_system_poll_interval_seconds seconds
ntp_system_poll_interval_seconds 16.00000000372529
# HELP ntp_system_poll_interval Exponent of time between poll intervals.
# TYPE ntp_system_poll_interval gauge
ntp_system_poll_interval 4.0
# HELP ntp_system_precision_seconds Precision of the local clock.
# TYPE ntp_system_precision_seconds gauge
# UNIT ntp_system_precision_seconds seconds
ntp_system_precision_seconds 0.000003814697266513178
# HELP ntp_system_accumulated_steps_seconds Accumulated amount of seconds that the system needed to jump the time.
# TYPE ntp_system_accumulated_steps_seconds gauge
# UNIT ntp_system_accumulated_steps_seconds seconds
ntp_system_accumulated_steps_seconds 0.0
# HELP ntp_system_accumulated_steps_threshold_seconds Threshold for the accumulated step amount at which the NTP daemon will exit (or -1 if no threshold was set).
# TYPE ntp_system_accumulated_steps_threshold_seconds gauge
# UNIT ntp_system_accumulated_steps_threshold_seconds seconds
ntp_system_accumulated_steps_threshold_seconds -1.0
# HELP ntp_system_leap_indicator Indicates that a leap second will take place.
# TYPE ntp_system_leap_indicator gauge
ntp_system_leap_indicator 3
# HELP ntp_peer_uptime_seconds Time since the peer was started.
# TYPE ntp_peer_uptime_seconds gauge
# UNIT ntp_peer_uptime_seconds seconds
ntp_peer_uptime_seconds{address="127.0.0.1:123"} 51
# HELP ntp_peer_poll_interval_seconds Time between polls of the peer.
# TYPE ntp_peer_poll_interval_seconds gauge
# UNIT ntp_peer_poll_interval_seconds seconds
ntp_peer_poll_interval_seconds{address="127.0.0.1:123"} 16.00000000372529
# HELP ntp_peer_poll_interval Exponent of time between polls of the peer.
# TYPE ntp_peer_poll_interval gauge
ntp_peer_poll_interval{address="127.0.0.1:123"} 4.0
# HELP ntp_peer_reachability_status Number of polls until the upstream server is unreachable, zero if it is.
# TYPE ntp_peer_reachability_status gauge
ntp_peer_reachability_status{address="127.0.0.1:123"} 8
# HELP ntp_peer_offset_seconds Offset between the upstream server and system time.
# TYPE ntp_peer_offset_seconds gauge
# UNIT ntp_peer_offset_seconds seconds
ntp_peer_offset_seconds{address="127.0.0.1:123"} 0.00004205643200363415
# HELP ntp_peer_delay_seconds Current round-trip delay to the upstream server.
# TYPE ntp_peer_delay_seconds gauge
# UNIT ntp_peer_delay_seconds seconds
ntp_peer_delay_seconds{address="127.0.0.1:123"} 0.00020051281903882344
# HELP ntp_peer_dispersion_seconds Maximum error of the clock.
# TYPE ntp_peer_dispersion_seconds gauge
# UNIT ntp_peer_dispersion_seconds seconds
ntp_peer_dispersion_seconds{address="127.0.0.1:123"} 0.0007732014639240694
# HELP ntp_peer_jitter_seconds Variance of network latency.
# TYPE ntp_peer_jitter_seconds gauge
# UNIT ntp_peer_jitter_seconds seconds
ntp_peer_jitter_seconds{address="127.0.0.1:123"} 0.000015067552900017188
# HELP ntp_server_received_packets Number of incoming received packets.
# TYPE ntp_server_received_packets counter
ntp_server_received_packets_total{listen_address="127.0.0.1:123"} 11
# HELP ntp_server_accepted_packets Number of packets accepted.
# TYPE ntp_server_accepted_packets counter
ntp_server_accepted_packets_total{listen_address="127.0.0.1:123"} 11
# HELP ntp_server_denied_packets Number of denied packets.
# TYPE ntp_server_denied_packets counter
ntp_server_denied_packets_total{listen_address="127.0.0.1:123"} 0
# HELP ntp_server_rate_limited_packets Number of rate limited packets.
# TYPE ntp_server_rate_limited_packets counter
ntp_server_rate_limited_packets_total{listen_address="127.0.0.1:123"} 0
# HELP ntp_server_response_send_errors Number of packets where there was an error responding.
# TYPE ntp_server_response_send_errors counter
ntp_server_response_send_errors_total{listen_address="127.0.0.1:123"} 0
# EOF

```

## Prometheus metrics exporter
Prometheus prefers to use a pull-based architecture via HTTP. To facilitate this
a separate executable `ntp-metrics-exporter` can be used. This will start up a
HTTP server and serve the metrics on the `/metrics` endpoint. By default the
metrics exporter listens on localhost port 9975, but this can be changed via
command line parameters, see `ntp-metrics-exporter --help` for details. Note
that the metrics exporter does not do any authentication or HTTPS, so if the
metrics are transferred via a public network you should add a reverse proxy that
does authentication and HTTPS termination if required. The metrics exported are
the same as with the `ntp-ctl prometheus` command.
