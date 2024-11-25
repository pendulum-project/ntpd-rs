# GPSd time source
Instead of using another NTP server as a time source, it is also possible to use time data from [GPSd](https://gpsd.gitlab.io/gpsd/) as a time source for ntpd-rs.
GPSd is able to interpret GPS signals from a GPS receiver, from which it can derive the current time.

GPSd can be added as a time source for ntpd-rs by adding the following to the configuration:
```toml
[[source]]
mode = "sock"
path = "/run/chrony.ttyAMA0.sock"
measurement_noise_estimate = 0.001
```
The `path` points to the location of the socket that GPSd writes timing data to. This socket was originally meant for chrony, but ntpd-rs also supports this same socket format. Here, `ttyAMA0` is the GPS receiver device used by GPSd.

The `measurement_noise_estimate` gives a static estimate of how noisy GPSd's timing data is. Normally with NTP time sources, we would use the network delay as an independent estimate of how noisy the data is. When using GPSd as a time source, we do not have a good estimate of the noise, so we use a static noise estimate instead.

## Setting up GPSd
In order for GPSd to connect to ntpd-rs, GPSd must be started after ntpd-rs. This is because ntpd-rs needs to create the socket, and GPSd will only use the socket if it exists when it starts.

GPSd can be manually restarted using:
```sh
sudo systemctl restart gpsd.socket
```

For help with setting up GPSd on e.g. a Raspberry Pi, see for example [this guide](https://n4bfr.com/2020/04/raspberry-pi-with-chrony/2/).

## Pulse Per Second (PPS)
Unfortunately, ntpd-rs does currently not yet support PPS timing data, but this may be added in the [future](https://github.com/pendulum-project/ntpd-rs/issues/882).
Some challenges still need to be solved in order to support PPS data in the Kalman filters used for noise filtering.
