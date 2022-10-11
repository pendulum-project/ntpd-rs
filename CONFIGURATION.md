# Configuring ntpd-rs

If you want to try out ntpd-rs on a non-critical system, this guide provides the basic information needed to properly build and configure ntpd-rs. This software SHOULD NOT be used on any system where you cannot handle either reliability or security issues.

## Limitations

The current implementation has several important limitations:

 - The current implementation is client-only, and does not support acting as an NTP server.
 - There is no support for broadcast client/server or symmetric active/passive connections, only acting as the client towards a server node is implemented.
 - DNS lookup is currently only done at startup. Changes in the IP address of a remote server are not picked up until a restart of the daemon.
 - There is no support for NTP pools yet. Multiple servers should be configured manually in the configuration file.
 - Changes in network interfaces are not picked up dynamically and will require a restart of the daemon.

## Building

Currently, ntpd-rs only supports Linux-based operating systems. Our current testing only targets Linux kernels after version 5.0.0, older kernels may work but this is not guaranteed.

ntpd-rs is written in rust, and requires cargo 1.60.0 at a minimum to be built. Earlier versions may work but are currently not included in our testing regime. We strongly recommend using [rustup](https://rustup.rs) to install rust/cargo, as the version provided by system package managers tend to be out of date.

To build ntpd-rs run:

```sh
cargo build --release
```

This produces a binary `ntp-daemon` in the `target/release` folder, which is the main NTP daemon. The daemon requires elevated permissions in order to change the system clock. It can be tested against a server in the [NTP pool](https://ntppool.org) (please ensure no other NTP daemons are running):

```sh
sudo ./target/release/ntp-daemon -p pool.ntp.org
```

After a few minutes you should start to see messages indicating the offset of your machine from the server.

## Configuration

The ntp-daemon binary can be configured through two channels: via command line options and via a configuration file. The command line options are primarily intended to tell ntp-daemon where to find its configuration file, and to override the most important settings when debugging problems. The configuration file is the preferred method of configuring ntp-daemon, and allows changing of settings not available through the command line.

### Command line options

The following command line options are available. When an option is not provided, the indicated default is used.

| Option | Default | Description |
| --- | --- | --- |
| `-c <FILE>`, `--config <FILE>` | First existing of `./ntp.toml`, `/etc/ntp.toml` | Which configuration file to use. When provided, the fallback locations are not used. |
| `-l <LEVEL>`, `--log-filter <LEVEL>` | From configuration file | Override for the configuration file `log-filter` parameter, see explanation there. |
| `-p <ADDR>`, `--peer <ADDR>` | | Setup a connection to the given server, overrides the peers in the configuration file. Can be given multiple times to configure multiple servers as reference. |

### Configuration file

The ntp-daemon's primary configuration method is through a TOML configuration file. By default, this is looked for first in the current working directory (e.g. under `./ntp.toml`), and next in the system-wide configuration directories under `/etc/ntp.toml`. A non-standard location can be provided via the `-c` or `--config` command line flags.

General options:
| Option | Default | Description |
| --- | --- | --- |
| log-filter | info | Set the amount of information logged. Available levels: trace, debug, info, warn. |

Peers are configured in the `peers` section. Per peer, the following options are available:
| Option | Default | Description |
| --- | --- | --- |
| addr | | Address of the remote server |
Note that peers can also be generated from simply a string containing the address, see also the example below.

The daemon can expose an observation socket that can be read to obtain information on the current state of the peer connections and clock steering algorithm. This socket can be configured via the `observe` sections:
| Option | Default | Description |
| --- | --- | --- |
| path | | Path on which the observation socket is exposed. If no path is given, the observation socket is disabled. |
| mode | 0o777 | Permissions with which the socket should be created, given as (octal) integer. |

The daemon can also expose a configuration socket that can be used to change some configuration options dynamically. This socket can be configured via the `configure` sections:
| Option | Default | Description |
| --- | --- | --- |
| path | | Path on which the configuration socket is exposed. If no path is given, the configuration socket is disabled. |
| mode | 0o770 | Permissions with which the socket should be created, given as (octal) integer. |

The management and configuration sockets are used by the [management client](MANAGEMENT_CLIENT.md) to display the daemon's state and to allow for dynamic changing of some configuration parameters.

There are a number of options available to influence how time differences to the various servers are used to synchronize the system clock. All of these are part of the `system` section of the configuration:
| Option | Default | Description |
| --- | --- | --- |
| min-intersection-survivors | 3 | Minimum number of servers that need to agree on the true time from our perspective for synchronization to start. |
| min-cluster-survivors | 3 | Number of servers beyond which we do not try to exclude further servers for the purpose of improving measurement precision. Do not change unless familiar with the NTP algorithms. |
| frequency-tolerance | 15 | Estimate of the short-time frequency precision of the local clock, in parts-per-million. The default is usually a good approximation. |
| distance-threshold | 1 | Maximum delay to the clock representing ground truth via a peer for that peer to be considered acceptable, in seconds. |
| frequency-measurement-period | 900 | Amount of time to spend on startup measuring the frequency offset of the system clock, in seconds. Lowering this means the clock is kept actively synchronized sooner, but reduces the precision of the initial frequency estimate, which could result in lower stability of the clock early on. |
| spike-threshold | 900 | Amount of time before a clock difference larger than 125ms is considered real instead of a spike in the network. Lower values ensure large errors are corrected faster, but make the client more sensitive to network issues. Value provided is in seconds. |
| panic-threshold | 1800 (symmetric) | Largest time difference the client is allowed to correct in one go. Differences beyond this cause the client to abort synchronization. Value provided is in seconds, set to 0 to disable checking of jumps. |
| startup-panic-threshold | No limit forward, 1800 backward | Largest time difference the client is allowed to correct during startup. By default, this is unrestricted as we may be the initial source of time for systems without a hardware backed clock. Value provided is in seconds, set to 0 to disable checking of jumps. |
| accumulated-threshold | Disabled | Total amount of time difference the client is allowed to correct using steps whilst running. By default, this is unrestricted. Value provided is in seconds, set to 0 to disable checking of accumulated steps. |

For panic thresholds, asymetric thresholds can be configured, allowing a different sized step going forwards compared to going backwards. This is done by configuring a struct with two values, `forward` and `backward` for the panic threshold.

An example of a configuration file is provided below:
```toml
# Other values include trace, debug, warn and error
log-filter = "info"

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
min-intersection-survivors = 1
min-cluster-survivors = 3
frequency-tolerance = 15
distance-threshold = 1
panic-threshold = 10
startup-panic-threshold = { forward = 0, backward = 1800 }
```

## Operational concerns

ntpd-rs controls the system clock. Because the effects of poor steering can lead to the system clock quickly losing all connection to reality, much more so than no steering, there are several situations where the NTP daemon will terminate itself rather than continue steering the clock. Because of this, rather than setting up automatic restart of the NTP daemon on failure, we strongly recommend requiring human intervention before a restart.

Should you still desire to automatically restart the NTP daemon, there are several considerations to take into account. First, to limit the amount of clock shift allowed during startup it is recommended to set the `startup-panic-threshold` configuration parameter to match the `panic-threshold` parameter. Doing so ensures that rebooting cannot unintentionally cause larger steps than allowed during normal operations.

Furthermore, if at all possible, rebooting should be limited to only those exit codes which are known to be caused by situations where a reboot is safe. In particular, the process should not be rebooted when exiting with status code 101, as this status code is returned when the NTP daemon detects abnormally large changes in the time indicated by the remote servers used.

More guidance on proper configuration for regular operation is given in the [operational considerations documentation](OPERATIONAL_CONSIDERATIONS.md)

## Systemd configuration

To run ntpd-rs as the system NTP service, the following systemd service definition can be used. Note that this service definition assumes that the ntp-daemon binary has been installed to `/usr/local/bin`, and that the configuration is stored in the default `/etc/ntp.toml` location. Furthermore, it assumes the existence of a low-privileged `ntpd-rs` group and user. Refer to your distribution's documentation for information on how to create such accounts.

Note that because of the aforementioned limitations around peer configuration, this service file requires the network-online target. As a result, using this may increase boot times significantly, especially on machines that do not have permanent network connectivity.

This service should not be used at the same time as other NTP services. It explicitly disables the systemd built-in timesyncd service, but be aware that your operating system may use another NTP service. Note also that the daemon SHOULD NOT be restarted when crashing without human intervention. See our [operational guidance](OPERATIONAL_CONSIDERATIONS.md) for more information on this.

```ini
[Unit]
Description=Rust Network Time Service
Documentation=https://github.com/memorysafety/ntpd-rs
After=network-online.target
Wants=network-online.target
Conflicts=systemd-timesyncd.service ntp.service

[Service]
Type=simple
Restart=no
ExecStart=/usr/local/bin/ntp-daemon
Environment="RUST_LOG=info"
User=ntpd-rs
Group=ntpd-rs
AmbientCapabilities=CAP_SYS_TIME

[Install]
WantedBy=multi-user.target
```
