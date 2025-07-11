# GPS / PPS time sources

## GPSd time source
Instead of using another NTP server as a time source, it is also possible to use time data from [GPSd](https://gpsd.gitlab.io/gpsd/) as a time source for ntpd-rs.
GPSd is able to interpret GPS signals from a GPS receiver, from which it can derive the current time.

To provide this information, gpsd tries to open a socket at `/run/chrony.XXXX.sock`, where `XXXX` is replaced with the device name of the GPS device. When running ntpd-rs with reduced permissions, this socket cannot be created by ntpd-rs. We therefore have to configure systemd (or an equivalent startup daemon) to create a symlink to a folder ntpd-rs can create the socket in. We recommend linking to `/run/ntpd-rs/chrony.XXXX.sock`, which can be done with the following systemd unit:
```ini
[Unit]
Description=GPSD Socket Shim
Documentation=https://github.com/pendulum-project/ntpd-rs

[Service]
Type=oneshot
ExecStart=/bin/bash -c "ln -s /run/ntpd-rs/chrony.XXXX.sock /run/chrony.XXXX.sock"
```

GPSd can then be added as a time source for ntpd-rs by adding the following to the configuration:
```toml
[[source]]
mode = "sock"
path = "/run/ntpd-rs/chrony.XXXX.sock"
precision = 1e-3
```

For socket sources such as a GPS device from gpsd, ntpd-rs is unable to estimate the uncertainty of the timing data. Therefore, you should provide an estimate (corresponding to 1 standard deviation) of this noise yourself through the `precision` field. For typical GPS receivers, an uncertainty somewhere in the range of 1 to 100 ms is reasonable.

### Setting up GPSd
In order for GPSd to connect to ntpd-rs, GPSd must start after ntpd-rs and after the socket shim has been created. This is because ntpd-rs needs to create the socket for GPSd, which can only find the socket if it exists at the moment GPSd starts.

GPSd can be manually restarted using:
```sh
sudo systemctl restart gpsd.socket
```

Systemd can be told to enforce such a starting order using the [`Wants`, `Before` and `After` keys in the `Unit` section](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#%5BUnit%5D%20Section%20Options). It is recommended to modify the unit files for ntpd-rs and gpsd through `systemctl edit` when making these changes.

For help with setting up GPSd on a Raspberry Pi, see for example [this guide](https://n4bfr.com/2020/04/raspberry-pi-with-chrony/2/).

## Pulse Per Second (PPS)
Ntpd-rs also supports using PPS timing data via Kernel PPS, based on [RFC 2783](https://datatracker.ietf.org/doc/html/rfc2783).

Here is an example configuration of a 1 PPS device in ntpd-rs:
```toml
[[source]]
mode = "pps"
path = "/dev/pps0"
precision = 1e-7
```

By default, PPS sources are treated as 1 PPS sources, which send a pulse every rounded second. For e.g. a 10 PPS device, the source can be configured with a period of 0.1 seconds:
```toml
[[source]]
mode = "pps"
path = "/dev/pps0"
precision = 1e-7
period = 0.1
```
