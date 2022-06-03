# Configuring NTPD-rs

NTPD-rs is an implementation of NTP completely written in Rust, with a focus on exposing a minimal attack surface. The project is currently in an early stage, but if you want to try out NTPD-rs on a non-critical system, this guide provides the basic information needed to properly build and configure NTPD-rs.

## Limitations

The current implementation has several important limitations which it is important to be aware of. First of all, the current implementation is an NTP client only, and does not support acting as an NTP server.

Second, there are currently a few limitations around configuring connections to other NTP nodes:
 - Only Client-Server connections are supported
 - DNS lookup is currently only done at startup. Changes in the IP address 
 - There is no support for NTP pools yet. Multiple 
 - Changes in network interfaces are not picked up dynamically and will require a reboot of the daemon.

Finally, please be aware that this is very early stage software, and is not yet ready for production software. This software SHOULD NOT be used on any system where you cannot handling experiencing issues, either reliability or security related.

## Building

Currently, NTPD-rs only support linux based operating systems. Our current testing only targets linux kernels after version 5.0.0, older kernels may work but are not guaranteed.

NTPD-rs is written in rust, and requires cargo 1.61.0 at a minimum to be built. We strongly recommend using [rustup](https://rustup.rs) to install rust/cargo, as the version provided by system package managers tend to be out of date.

To build NTPD-rs run
```sh
cargo build --release
```
This produces a binary `ntp-daemon` in the `target/release` folder, which is the main ntp daemon. The daemon requires elevated permissions in order to change the system clock. It can be tested against a server in the [ntp pool](https://ntppool.org) (please ensure no other ntp daemons are running)
```sh
sudo ./target/release/ntp-daemon -p pool.ntp.org
```
After a few minutes you should start to see messages indicating the offset of your machine from the server.

## Configuration

The ntp-daemon binary can be configured through two channels: via command line options and via a configuration file. The command line options are primarily intended to tell ntp-daemon where to find its configuration file, and to override the most important settings when debugging problems. The configuration file is the preferred method of configuring ntp-daemon, and allows changing of settings not availble through the command line.

### Command line options

The following command line options are available. When an option is not provided, the indicated default is used.

| Option | Default | Description |
| --- | --- | --- |
| `-c <FILE>`, `--config <FILE>` | First existing of ./ntp.toml, /etc/ntp.toml | Which configuration file to use. When provided, the fallback locations are not used. |
| `-l <LEVEL>`, `--log-filter <LEVEL>` | From configuration file | Set the ammount of information logged, overrides the configuration file. Avaible levels: trace, debug, info, warn, error |
| `-p <ADDR>`, `--peer <ADDR>` | | Setup a connection to the given server, overrides the peers in the configuration file. Can be given multiple times to configure multiple servers as reference |

### Configuration file

The ntp-daemon's primary configuration method is through a toml configuration file. By default, this is looked for first in the current working directory (e.g. under `./ntp.toml`), and next in the system-wide configuration directories under `/etc/ntp.toml`. A non-standard location can be provided via the `-c` or `--config` command line flags.

General options:
| Option | Default | Description |
| --- | --- | --- |
| log_filter | info | Set the ammount of information logged. Available levels: trace, debug, info, warn |

Peers are configured in the `peers` list. Per peer, the following options are available:
| Option | Default | Description |
| --- | --- | --- |
| addr | | Address of the remote server |
Note that peers can also be generated from simply a string containing the address, see alos the example below.

There are a number of options available to influence how the time differences to the various servers are used to synchronize the system clock. All of these are part of the `system` section of the configuration:
| Option | Default | Description |
| --- | --- | --- |
| min_intersection_survivors | 1 | Minimum number of servers that need to agree on the true time from our perspective for synchronization to start. |
| min_cluster_survivors | 3 | Number of servers beyond which we do not try to exclude further servers for the purpose of improving measurement precision. Do not change unless familiar with the NTP algorithms. |
| frequency_tolerance | 15 | Estimate of the short-time frequency precision of the local clock, in parts-per-million. The default is usually a good approximation. |
| distance_threshold | 1 | Maximum delay to the clock representing ground truth via a peer for that peer to be considered acceptable, in seconds. |
| frequency_measurement_period | 900 | Amount of time to spend on startup measuring the frequency offset of the system clock, in seconds. Lowering this means the clock is kept actively synchronized sooner, but reduces the precision of the initial frequency estimate, which could result in lower stability of the clock early on. |
| spike_threshold | 900 | Amount of time before a clock difference larger than 125ms is considered real instead of a spike in the network. Lower values ensure large errors are corrected faster, but make the client more sensitive to network issues. Value provided is in seconds. |
| panic_threshold | 1800 | Largest time difference the client is allowed to correct in one go. Differences beyond this cause the client to abort synchronziation. Value provided is in seconds, set to 0 to disable checking of jumps. |
| startup_panic_threshold | Disabled | Largest time difference the client is allowed to correct during startup. By default, this is unrestricted as we may be the initial source of time for systems without a hardware backed clock. Value provided is in seconds, set to 0 to disable checking of jumps. |

An example of a configuration file is provided below:
```toml
# Other options include trace, debug, warn and error
log_filter = "info"

# Peers can be configured as a simple list (pool servers from ntppool.org)
peers = ["0.pool.ntp.org", "1.pool.ntp.org", "2.pool.ntp.org", "3.pool.ntp.org"]

# Or by providing written out configuration
# [[peers]]
# addr = "0.pool.ntp.org:123"
#

# [[peers]]
# addr = "1.pool.ntp.org:123"

# System parameters used in filtering and steering the clock:
[system]
min_intersection_survivors = 1
min_cluster_survivors = 3
frequency_tolerance = 15
distance_threshold = 1
```

## Operational concerns

NTPD-rs controls the system clock. Because the effects of poor steering can lead to the system clock quickly losing all connection to reality, much more so than no steering, there are several situations where the ntp daemon will terminate itself rather than continue steering the clock. Because of this, rather than setting up automatic restart of the ntp daemon on failure, we strongly recommend requiring human intervention before restart.

Should you still desire to automatically restart the NTP daemon, there are several considerations to take into account. First, to limit the ammount of clock shift allowed during startup it is recommended to set the startup_panic_threshold configuration parameter to match the panic_threshold parameter. Doing so ensures that rebooting cannot unintenionally cause larger steps than allowed during normal operations.

Furthermore, if at all possible, rebooting should be limited to only those exit codes which are known to be caused by situations where a reboot is safe. In particular, the process should not be rebooted when exiting with status code 101, as this status code is returned when the ntp daemon detects abnormally large changes in the time indicated by the remote servers used.

## Systemd configuration

To run NTPD-rs as the system ntp service, the following systemd service definition can be used. Note that this service definition assumes that the ntp-daemon binary has bin installed to /usr/local/bin, and that the configuration is stored in the default /etc/ntp.toml location.

Note that because of the aformentioned limitations around peer configuration, this service file requires the network-online target. As a result, using this may increase boot times signifcantly, especially on machines that do not have permanent network connectivity.

This service should not be used at the same time as other ntp services. It explicitly disables the systemd built-in timesyncd service, but be aware that your operating system may use another ntp service.

```ini
[Unit]
Description=Rust Network Time Service
Documentation=https://github.com/memorysafety/ntpd-rs
After=network-online.target
Wants=network-online.target
Conflicts=systemd-timesyncd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/ntp-daemon

[Install]
WantedBy=multi-user.target
```
