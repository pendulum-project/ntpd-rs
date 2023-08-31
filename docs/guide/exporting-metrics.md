# Exporting metrics

Ntpd-rs comes with support for exporting key operational metrics to an external prometheus instance. Configuring this requires two things:
- Enabling the observability socket in the ntpd-rs configuration.
- Configure the system to run ntp-metrics-exporter as a service.

Enabling the observability socket requires the following to be present in the configuration:
```toml
[observability]
observation-path = "/run/ntpd-rs/observe"
```
This line is already present in the default configuration if nptd-rs was installed from our packages.

## Installed from package

If ntpd-rs was installed from the packages distributed by us, the default configuration will already have enabled the observation socket. Furthermore, these packages contain a systemd unit file that enables the metrics exporter with a reasonable configuration. This can be enabled with
```sh
sudo systemctl enable --now ntpd-rs-metrics
```

After enabling the metrics exporter, a prometheus metrics dataset will be served on `127.0.0.1:9975/metrics`

## Installed through cargo or from source

When installed through cargo or from source, you will have to manually configure your system to run the ntp-metrics-exporter binary as a service. For systemd based systems, an example is provided below.
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
