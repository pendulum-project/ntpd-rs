# GPS / PPS time sources

## GPSd time source
Instead of using another NTP server as a time source, it is also possible to use time data from [GPSd](https://gpsd.gitlab.io/gpsd/) as a time source for ntpd-rs.
GPSd is able to interpret GPS signals from a GPS receiver, from which it can derive the current time.

GPSd can be added as a time source for ntpd-rs by adding the following to the configuration:
```toml
[[source]]
mode = "sock"
path = "/run/chrony.ttyAMA0.sock"
measurement_noise_estimate = 1e-6
```
The `path` points to the location of the socket that GPSd writes timing data to. This socket was originally meant for chrony, but ntpd-rs also supports this same socket format. Here, `ttyAMA0` is the GPS receiver device used by GPSd.

The `measurement_noise_estimate` gives a static estimate of how noisy GPSd's timing data is. Normally with NTP time sources, we would use the network delay as an independent estimate of how noisy the data is. When using GPSd as a time source, we do not have a good estimate of the noise, so we use a static noise estimate instead. The noise estimate should be a quarter of the expected variance.

### Setting up GPSd
In order for GPSd to connect to ntpd-rs, GPSd must start after ntpd-rs. This is because ntpd-rs needs to create a socket which GPSd will only use if it exists when GPSd starts.

GPSd can be manually restarted using:
```sh
sudo systemctl restart gpsd.socket
```

For help with setting up GPSd on e.g. a Raspberry Pi, see for example [this guide](https://n4bfr.com/2020/04/raspberry-pi-with-chrony/2/).

## Pulse Per Second (PPS)
Ntpd-rs also supports using PPS timing data via Kernel PPS, based on [RFC 2783](https://datatracker.ietf.org/doc/html/rfc2783).

Here is an example configuration of a 1 PPS device in ntpd-rs:
```toml
[[source]]
mode = "pps"
path = "/dev/pps0"
measurement_noise_estimate = 1e-14
```

By default, PPS sources are treated as 1 PPS sources, which send a pulse every rounded second. For e.g. a 10 PPS device, the source can be configured with a period of 0.1 seconds:
```toml
[[source]]
mode = "pps"
path = "/dev/pps0"
measurement_noise_estimate = 1e-14
period = 0.1
```
