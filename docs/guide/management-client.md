# Management client

**The management client interface format is unstable! Do you have suggestion
for additional values to expose? let us know in an issue!**

ntpd-rs comes with a management client for the daemon. This client can show the
current state of the daemon, as well as change the log level and panic
thresholds of the daemon.

## Enabling the management client

In order to communicate with the daemon, the management client relies on two
sockets, an observation socket and a configuration socket, which are disabled
by default. To enable use of the client, these sockets should be enabled in
the configuration. On Linux, it is common to place these sockets in a
subdirectory of `/run` specific to the daemon.

The client can run with only one of the sockets enabled. In that situation, not
all functionality is available. The same holds when the currently running user
has insufficient permissions for one of the sockets.

For the configuration socket, default permissions restrict access to the group
under which the server is running. Users should be added to this group when
they need to be able to change configuration settings of the daemon dynamically.

## Using the management client

The current client exposes 3 different commands:
- `ntp-ctl sources` displays information on the currently active source connections
- `ntp-ctl system` displays information on the current synchronization state of
  the system.
- `ntp-ctl prometheus` combines output of `ntp-ctl sources` and `ntp-ctl system`
  in the prometheus export format
- `ntp-ctl config` allows changing of some configuration parameters

## Available configuration parameters

Currently, only the `log-level` configuration parameter can be set dynamically,
through the `--log-level` command line parameter. For information on the
allowed values, see the configuration documentation.

## Specifying socket locations

By default, the management client looks for the daemon's configuration in
`/etc/ntpd-rs/ntp.toml` in order to extract the paths of the socket. If this
file is not present, or when the socket paths are not configured in these, it
defaults to `/run/ntpd-rs/observe` for the observation socket and
`/run/ntpd-rs/configure` for the configuration sockets.

If the client fails to find the correct socket paths using the above process,
it can be manually configured to look elsewhere. Most advisable is to point
the management client to the configuration file of the server via the
`--config` command line flag.

## Output format

Output is given as formatted json

**peer:**
```
[
  {
    "Observable": {
      "offset": 0.002731145127380999,
      "uncertainty": 0.0010577326177288156,
      "delay": 0.007663535188805204,
      "remote_delay": 0.020446777348510636,
      "remote_uncertainty": 0.06361389161637376,
      "last_update": {
        "timestamp": 16662280508228141032
      },
      "reachability": 255,
      "poll_interval": 4,
      "peer_id": 89091106,
      "address": "0.pool.ntp.org:123"
    }
  },
  {
    "Observable": {
      "offset": 0.0032871617011928844,
      "uncertainty": 0.0006341086702035062,
      "delay": 0.0108117456573089,
      "remote_delay": 0.000015258789066052714,
      "remote_uncertainty": 0.000015258789066052714,
      "last_update": {
        "timestamp": 16662280293865599110
      },
      "reachability": 255,
      "poll_interval": 4,
      "peer_id": 1590075152,
      "address": "1.pool.ntp.org:123"
    }
  }
]

```

**system:**
```
{
  "stratum": 2,
  "reference_id": 1414352460,
  "accumulated_steps_threshold": null,
  "poll_interval": 4,
  "precision": 3.814697266513178e-6,
  "root_delay": 0.012669552819027928,
  "root_dispersion": 0.9487744674432963,
  "leap_indicator": "NoWarning",
  "accumulated_steps": 0.009811621860091487
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
ntp_system_accumulated_steps_seconds 0.009811621860091488
# HELP ntp_system_accumulated_steps_threshold_seconds Threshold for the accumulated step amount at which the NTP daemon will exit (or -1 if no threshold was set).
# TYPE ntp_system_accumulated_steps_threshold_seconds gauge
# UNIT ntp_system_accumulated_steps_threshold_seconds seconds
ntp_system_accumulated_steps_threshold_seconds -1.0
# HELP ntp_system_leap_indicator Indicates that a leap second will take place.
# TYPE ntp_system_leap_indicator gauge
ntp_system_leap_indicator 0
# HELP ntp_peer_uptime_seconds Time since the peer was started.
# TYPE ntp_peer_uptime_seconds gauge
# UNIT ntp_peer_uptime_seconds seconds
ntp_peer_uptime_seconds{address="1.pool.ntp.org:123"} -10.098467026394435
ntp_peer_uptime_seconds{address="0.pool.ntp.org:123"} 23.02104354207894
# HELP ntp_peer_poll_interval_seconds Time between polls of the peer.
# TYPE ntp_peer_poll_interval_seconds gauge
# UNIT ntp_peer_poll_interval_seconds seconds
ntp_peer_poll_interval_seconds{address="0.pool.ntp.org:123"} 16.00000000372529
ntp_peer_poll_interval_seconds{address="1.pool.ntp.org:123"} 16.00000000372529
# HELP ntp_peer_poll_interval Exponent of time between polls of the peer.
# TYPE ntp_peer_poll_interval gauge
ntp_peer_poll_interval{address="0.pool.ntp.org:123"} 4.0
ntp_peer_poll_interval{address="1.pool.ntp.org:123"} 4.0
# HELP ntp_peer_reachability_status Number of polls until the upstream server is unreachable, zero if it is.
# TYPE ntp_peer_reachability_status gauge
ntp_peer_reachability_status{address="1.pool.ntp.org:123"} 8
ntp_peer_reachability_status{address="0.pool.ntp.org:123"} 8
# HELP ntp_peer_offset_seconds Offset between the upstream server and system time.
# TYPE ntp_peer_offset_seconds gauge
# UNIT ntp_peer_offset_seconds seconds
ntp_peer_offset_seconds{address="0.pool.ntp.org:123"} 0.0038458579228832056
ntp_peer_offset_seconds{address="1.pool.ntp.org:123"} 0.00432991446096681
# HELP ntp_peer_delay_seconds Current round-trip delay to the upstream server.
# TYPE ntp_peer_delay_seconds gauge
# UNIT ntp_peer_delay_seconds seconds
ntp_peer_delay_seconds{address="1.pool.ntp.org:123"} 0.010786478875853699
ntp_peer_delay_seconds{address="0.pool.ntp.org:123"} 0.00760143553083796
# HELP ntp_peer_uncertainty_seconds Estimated error of the clock.
# TYPE ntp_peer_uncertainty_seconds gauge
# UNIT ntp_peer_uncertainty_seconds seconds
ntp_peer_uncertainty_seconds{address="1.pool.ntp.org:123"} 0.0008779882921087529
ntp_peer_uncertainty_seconds{address="0.pool.ntp.org:123"} 0.0009309677409313078
# HELP ntp_server_received_packets Number of incoming received packets.
# TYPE ntp_server_received_packets counter
# HELP ntp_server_accepted_packets Number of packets accepted.
# TYPE ntp_server_accepted_packets counter
# HELP ntp_server_denied_packets Number of denied packets.
# TYPE ntp_server_denied_packets counter
# HELP ntp_server_ignored_packets Number of packets ignored.
# TYPE ntp_server_ignored_packets counter
# HELP ntp_server_rate_limited_packets Number of rate limited packets.
# TYPE ntp_server_rate_limited_packets counter
# HELP ntp_server_response_send_errors Number of packets where there was an error responding.
# TYPE ntp_server_response_send_errors counter
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
