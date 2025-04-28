# Exporting metrics

Ntpd-rs supports exporting key operational metrics to an external [prometheus](https://prometheus.io/) instance.

## Installed from package

If ntpd-rs was installed from the packages distributed by us, the default configuration will already have enabled the observation socket. Furthermore, these packages contain a systemd unit file that enables the metrics exporter with a reasonable configuration. This can be enabled with
```sh
sudo systemctl enable --now ntpd-rs-metrics
```

After enabling the metrics exporter, a prometheus metrics dataset will be served on `127.0.0.1:9975/metrics` by default. This can be adjusted with the following configuration section in [ntp.toml](../man/ntp.toml.5.md#observability) to expose this to Prometheus:

```toml
[observability]
metrics-exporter-listen = "[::]:9975"
```

Be sure to firewall this port so that only Prometheus instances have access.

## Metrics

The dataset will look something like:
```
# HELP ntp_uptime_seconds Time that the ntp daemon is running.
# TYPE ntp_uptime_seconds gauge
# UNIT ntp_uptime_seconds seconds
ntp_uptime_seconds{version="1.3.0",build_commit="e8869f4378971ca470131e54fea6e72655a774c3",build_commit_date="2024-09-19"} 1320106.480437661
# HELP ntp_system_poll_interval_seconds [DEPRECATED] Time between polls of the system.
# TYPE ntp_system_poll_interval_seconds gauge
# UNIT ntp_system_poll_interval_seconds seconds
ntp_system_poll_interval_seconds 256.00000005960464
# HELP ntp_system_accumulated_steps_seconds Accumulated amount of seconds that the system needed to jump the time.
# TYPE ntp_system_accumulated_steps_seconds gauge
# UNIT ntp_system_accumulated_steps_seconds seconds
ntp_system_accumulated_steps_seconds 0
# HELP ntp_system_accumulated_steps_threshold_seconds Threshold for the accumulated step amount at which the NTP daemon will exit (or -1 if no threshold was set).
# TYPE ntp_system_accumulated_steps_threshold_seconds gauge
# UNIT ntp_system_accumulated_steps_threshold_seconds seconds
ntp_system_accumulated_steps_threshold_seconds -1
# HELP ntp_system_leap_indicator Indicates that a leap second will take place.
# TYPE ntp_system_leap_indicator gauge
ntp_system_leap_indicator 0
# HELP ntp_system_root_delay_seconds Distance to the closest root time source.
# TYPE ntp_system_root_delay_seconds gauge
# UNIT ntp_system_root_delay_seconds seconds
ntp_system_root_delay_seconds 0.006932416233916864
# HELP ntp_system_root_dispersion_seconds Estimate of how precise our time is.
# TYPE ntp_system_root_dispersion_seconds gauge
# UNIT ntp_system_root_dispersion_seconds seconds
ntp_system_root_dispersion_seconds 0.000041443621749394485
# HELP ntp_system_stratum Stratum of our clock.
# TYPE ntp_system_stratum gauge
ntp_system_stratum 2
# HELP ntp_source_poll_interval_seconds Time between polls of the source.
# TYPE ntp_source_poll_interval_seconds gauge
# UNIT ntp_source_poll_interval_seconds seconds
ntp_source_poll_interval_seconds{name="ntp.vsl.nl:123",address="31.223.173.226:123",id="1"} 256.00000005960464
# HELP ntp_source_unanswered_polls Number of polls since the last successful poll with a maximum of eight.
# TYPE ntp_source_unanswered_polls gauge
ntp_source_unanswered_polls{name="ntp.vsl.nl:123",address="31.223.173.226:123",id="1"} 0
# HELP ntp_source_offset_seconds Offset between the upstream source and system time.
# TYPE ntp_source_offset_seconds gauge
# UNIT ntp_source_offset_seconds seconds
ntp_source_offset_seconds{name="ntp.vsl.nl:123",address="31.223.173.226:123",id="1"} 0.000004342757166443103
# HELP ntp_source_delay_seconds Current round-trip delay to the upstream source.
# TYPE ntp_source_delay_seconds gauge
# UNIT ntp_source_delay_seconds seconds
ntp_source_delay_seconds{name="ntp.vsl.nl:123",address="31.223.173.226:123",id="1"} 0.006932416233916864
# HELP ntp_source_uncertainty_seconds Estimated error of the source clock.
# TYPE ntp_source_uncertainty_seconds gauge
# UNIT ntp_source_uncertainty_seconds seconds
ntp_source_uncertainty_seconds{name="ntp.vsl.nl:123",address="31.223.173.226:123",id="1"} 0.0000629844144133349
# HELP ntp_source_root_delay_seconds Root delay reported by the time source.
# TYPE ntp_source_root_delay_seconds gauge
# UNIT ntp_source_root_delay_seconds seconds
ntp_source_root_delay_seconds{name="ntp.vsl.nl:123",address="31.223.173.226:123",id="1"} 0
# HELP ntp_source_root_dispersion_seconds Uncertainty reported by the time source.
# TYPE ntp_source_root_dispersion_seconds gauge
# UNIT ntp_source_root_dispersion_seconds seconds
ntp_source_root_dispersion_seconds{name="ntp.vsl.nl:123",address="31.223.173.226:123",id="1"} 0.000015258789066052714
# HELP ntp_server_received_packets_total Number of incoming packets.
# TYPE ntp_server_received_packets_total counter
ntp_server_received_packets_total{listen_address="0.0.0.0:123"} 94633291
# HELP ntp_server_accepted_packets_total Number of packets accepted.
# TYPE ntp_server_accepted_packets_total counter
ntp_server_accepted_packets_total{listen_address="0.0.0.0:123"} 93203603
# HELP ntp_server_denied_packets_total Number of denied packets.
# TYPE ntp_server_denied_packets_total counter
ntp_server_denied_packets_total{listen_address="0.0.0.0:123"} 0
# HELP ntp_server_ignored_packets_total Number of packets ignored.
# TYPE ntp_server_ignored_packets_total counter
ntp_server_ignored_packets_total{listen_address="0.0.0.0:123"} 1429688
# HELP ntp_server_rate_limited_packets_total Number of rate limited packets.
# TYPE ntp_server_rate_limited_packets_total counter
ntp_server_rate_limited_packets_total{listen_address="0.0.0.0:123"} 0
# HELP ntp_server_response_send_errors_total Number of packets where there was an error responding.
# TYPE ntp_server_response_send_errors_total counter
ntp_server_response_send_errors_total{listen_address="0.0.0.0:123"} 2
# HELP ntp_server_nts_received_packets_total Number of incoming NTS packets.
# TYPE ntp_server_nts_received_packets_total counter
ntp_server_nts_received_packets_total{listen_address="0.0.0.0:123"} 0
# HELP ntp_server_nts_accepted_packets_total Number of NTS packets accepted.
# TYPE ntp_server_nts_accepted_packets_total counter
ntp_server_nts_accepted_packets_total{listen_address="0.0.0.0:123"} 0
# HELP ntp_server_nts_denied_packets_total Number of denied NTS packets.
# TYPE ntp_server_nts_denied_packets_total counter
ntp_server_nts_denied_packets_total{listen_address="0.0.0.0:123"} 0
# HELP ntp_server_nts_rate_limited_packets_total Number of rate limited NTS packets.
# TYPE ntp_server_nts_rate_limited_packets_total counter
ntp_server_nts_rate_limited_packets_total{listen_address="0.0.0.0:123"} 0
# HELP ntp_server_nts_nak_packets_total Number of NTS nak responses to packets.
# TYPE ntp_server_nts_nak_packets_total counter
ntp_server_nts_nak_packets_total{listen_address="0.0.0.0:123"} 0
# EOF
```

## Installed through cargo or from source

When installed through cargo or from source, two things need to be configured manually: 

- Enable the observability socket in the ntpd-rs configuration.
- Configure the system to run ntp-metrics-exporter as a service.

The observability socket can be enabled by adding the following to the configuration:
```toml
[observability]
observation-path = "/var/run/ntpd-rs/observe"
```

Next, configure your system to run the ntp-metrics-exporter binary as a service. For systemd based systems, an example is provided below.
```ini
[Unit]
Description=Network Time Service (ntpd-rs) metrics exporter
Documentation=https://github.com/pendulum-project/ntpd-rs

[Service]
Type=simple
Restart=yes
ExecStart=/usr/bin/ntp-metrics-exporter
Environment="RUST_LOG=info"
RuntimeDirectory=ntpd-rs-observe
User=ntpd-rs-observe
Group=ntpd-rs-observe

[Install]
WantedBy=multi-user.target
```
