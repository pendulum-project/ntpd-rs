# Configuring ntpd-rs

If you want to try out ntpd-rs, this guide provides the basic information needed to properly build and configure ntpd-rs.

## Limitations

Unlike the ntp reference implementation, ntpd-rs does not support either broadcast or symmetric modes, nor is there any plan to do so in the future. The decision to exclude these modes was taken because their design leaves them relatively vulnerable to security issues, and this is not easily mitigated. Furthermore, use of these modes can be replaced with client-server mode connections in almost all cases at a minimal cost in convenience and network traffic.

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

### RFC5905 compliant algorithm

By default, NTPD-rs uses a newer, better performing clock algorithm. This algorithm doesn't conform to the specification in RFC5905, but offers significantly better performance. Experience with both it and Chrony's non-standard algorithm indicates that a different clock algorithm does not impede interoperability.

However, should you desire to run an ntp instance that is to the largest extent possible RFC5905 compliant, it is possible to compile NTPD-rs with the clock algorithm from RFC5905. To do this, at build time the additional flags `--features rfc-algorithm` need to be added to the build command. Please note that when using the RFC's clock algorithm, a different set of configuration options needs to be used to tune it, as indicated below.

## Configuration

The ntp-daemon binary can be configured through two channels: via command line options and via a configuration file. The command line options are primarily intended to tell ntp-daemon where to find its configuration file, and to override the most important settings when debugging problems. The configuration file is the preferred method of configuring ntp-daemon, and allows changing of settings not available through the command line.

### Command line options

The following command line options are available. When an option is not provided, the indicated default is used.

| Option | Default | Description |
| --- | --- | --- |
| `-c <FILE>`, `--config <FILE>` | First existing of `./ntp.toml`, `/etc/ntp.toml` | Which configuration file to use. When provided, the fallback locations are not used. |
| `-l <LEVEL>`, `--log-filter <LEVEL>` | From configuration file | Override for the configuration file `log-filter` parameter, see explanation there. |
| `-p <ADDR>`, `--peer <ADDR>` | | Setup a connection to the given server, overrides the peers in the configuration file. Can be given multiple times to configure multiple servers as reference. |
| `-s <ADDR>`, `--server <ADDR>` | | Respond as NTP server to packets arriving to the given address, overrides server configuration in the configuration file. Can be given multiple times to attach as NTP server to multiple network interfaces. |

### Configuration file

The ntp-daemon's primary configuration method is through a TOML configuration file. By default, this is looked for first in the current working directory (e.g. under `./ntp.toml`), and next in the system-wide configuration directories under `/etc/ntp.toml`. A non-standard location can be provided via the `-c` or `--config` command line flags.

#### General options

| Option | Default | Description |
| --- | --- | --- |
| log-filter | info | Set the amount of information logged. Available levels: trace, debug, info, warn. |

#### Peer configuration

Peers are configured in the peers section, which should consist of a list of peers. Per peer, the following options are available:
| Option | Default | Description |
| --- | --- | --- |
| mode | server | Type of peer connection to create. Can be any of `server`, `nts-server` or `pool` (for meaning of these, see below). |
| addr | | Address of the server or pool. The default port (123) is automatically appended if not given. (not valid for nts connections) |
| addr-ke | | Address of the nts server. The default port (4460) is automatically appended if not given. (only valid for nts connections) |
| max-peers | 1 | Maximum number of peers to create from the pool. (only  valid for pools) |
| certificates | | Path to a pem file containing additional root certificates to accept for the TLS connection to the nts server. In addition to these certificates, the system certificates will also be accepted. (only valid for nts connections) |

##### Server peers

Server peers are direct NTP connections to a single remote server. This is the default. In addition to being able to be configured as a struct, they can also be configured from a string. This is useful when defining multiple servers. For example:

```
# As a simple list (pool servers from ntppool.org)
peers = ["0.pool.ntp.org", "1.pool.ntp.org", "2.pool.ntp.org", "3.pool.ntp.org"]

# Or by providing written out configuration
[[peers]]
addr = "0.pool.ntp.org:123"

[[peers]]
addr = "1.pool.ntp.org:123"
```

##### Nts peers

A peer in `server-nts` mode will use NTS (Network Times Security) to communicate with its server. The server must support NTS. The configuration requires the address of the Key Exchange server (the address of the actual NTP server that ends up being used may be different). For example:

```
[[peers]]
mode = "server-nts"
ke_addr = "time.cloudflare.com:4460"
certificate = "/path/to/certificates.pem"
```

##### Pool

`Pool` mode is a convenient way to configure many NTP servers, without having to worry about individual servers' IP addresses.

A peer in `Pool` mode will try to acquire `max_peers` addresses of NTP servers from the pool. `ntpd-rs` will actively try to keep a pool filled up. For instance if a server cannot be reached, a different server will be picked from the pool.

An example configuration for the ntppool.org ntp pool can look like
```
[[peers]]
addr = "pool.ntp.org"
mode = "Pool"
max_peers = 4
```

#### Server

Interfaces on which to act as a server are configured in the `server` section. Per interface configured, the following options are available:
| Option | Default | Description |
| --- | --- | --- |
| addr | | Address of the interface to bind to. |
| allowlist | ["0.0.0.0/0", "::/0"] | List of IP subnets allowed to contact through this interface. |
| allowlist-action | | Action taken when a client's IP is not on the list of allowed clients. Can be `Ignore` to ignore packets from such clients, or `Deny` to send a deny response to those clients. |
| denylist | [] | List of IP subnets disallowed to contact through this interface. |
| denylist-action | | Action taken when a client's IP is on the list of denied clients. Can be `Ignore` to ignore packets from such clients, or `Deny` to send a deny response to those clients. |
| rate-limiting-cache-size | 0 | How many clients to remember for the purpose of rate limiting. Increasing this number also decreases the probability of two clients sharing an entry in the table. A size of 0 disables rate limiting. |
| rate-limiting-cutoff-ms | 1000 | Minimum time between two client requests from the same IP address, in milliseconds. When a client send requests closer together than this it is sent a rate limit message instead of a normal time-providing response. |

For rate limiting, the server uses a hashtable to store when it has last seen a client. On a hash collision, the previous entry at that position is evicted. At small table sizes, this might reduce the effectiveness of ratelimiting when combined with high overall server load.

In applying the three client filters (deny, allow and ratelimiting), the server first checks whether the clients IP is on the denylist, then it checks whether it is on the allowlist, and finally it checks whether the client needs to be rate-limited. At each of these stages, the appropriate action is taken when the client fails the check.

#### NTS Server

Servers configured via the `server` section can also support NTS. To enable this, the built-in NTS-KE server needs to be enabled (hosting the NTS-KE server separately is not yet supported). This can be configured through the `nts-ke` section:
| Option | Default | Description |
| --- | --- | --- |
| cert-chain-path | | Path to the full chain TLS certificate for the server. Note that currently self-signed certificates are not supported. |
| key-der-path | | Path to the TLS private key for the server. |
| timeout-ms | 1000 | Timeout on NTS-KE sessions, after which the server decides to hang up. This is to prevent large resource utilization from old and or inactive sessions. Timeout duration is in milliseconds. |
| addr | | Address of the interface to bind to for the NTS-KE server. |

Our implementation of NTS follows the recommendations of section 6 in [RFC8915](https://www.rfc-editor.org/rfc/rfc8915.html). Currently, the master keys for encryption of the cookies are generated internally, and their generation can be controlled via the settings in the `keyset` section
| Option | Default | Description |
| --- | --- | --- |
| old-keys | 7 | Number of old keys to keep valid for existing cookies. |
| rotation-interval | 86400 | Time (in seconds) between generating new keys. |
| storage-path | | If specified, server keys are saved and restored from this path. This enables reboots of the server without invalidating the cookies of existing clients. |

##### A note on TLS keys and certificates

Due to limitations in rustls, we currently do not support self-signed certificates on either the client or the server. For public NTS-enabled server this shouldn't be a problem, as those should have certificates signed by one of the big root CA's. For private servers, this means you will have to setup a private CA and use it to sign the certificate of the server. This additional CA can then be provided to the clients.

Instructions for how to generate a CA certificate and use it to sign certificates can be found in many places on the internet, for example in this [github gist](https://gist.github.com/Soarez/9688998)

#### Observability and dynamic configuration

The daemon can expose an observation socket that can be read to obtain information on the current state of the peer connections and clock steering algorithm. This socket can be configured via the `observe` section:
| Option | Default | Description |
| --- | --- | --- |
| path | | Path on which the observation socket is exposed. If no path is given, the observation socket is disabled. |
| mode | 0o777 | Permissions with which the socket should be created, given as (octal) integer. |

The daemon can also expose a configuration socket that can be used to change some configuration options dynamically. This socket can be configured via the `configure` section:
| Option | Default | Description |
| --- | --- | --- |
| path | | Path on which the configuration socket is exposed. If no path is given, the configuration socket is disabled. |
| mode | 0o770 | Permissions with which the socket should be created, given as (octal) integer. |

The management and configuration sockets are used by the [management client](MANAGEMENT_CLIENT.md) to display the daemon's state and to allow for dynamic changing of some configuration parameters.

#### Time synchronization

There are a number of options available to influence how time differences to the various servers are used to synchronize the system clock. All of these are part of the `system` section of the configuration:
| Option | Default | Description |
| --- | --- | --- |
| min-intersection-survivors | 3 | Minimum number of servers that need to agree on the true time from our perspective for synchronization to start. |
| panic-threshold | 1800 (symmetric) | Largest time difference the client is allowed to correct in one go. Differences beyond this cause the client to abort synchronization. Value provided is in seconds, set to "inf" to disable checking of jumps. Setting this to 0 will disable time jumps except at startup. |
| startup-panic-threshold | No limit forward, 1800 backward | Largest time difference the client is allowed to correct during startup. By default, this is unrestricted as we may be the initial source of time for systems without a hardware backed clock. Value provided is in seconds, set to "inf" to disable checking of jumps. |
| accumulated-threshold | Disabled | Total amount of time difference the client is allowed to correct using steps whilst running. By default, this is unrestricted. Value provided is in seconds, set to 0 to disable checking of accumulated steps. |
| local-stratum | 16 | Stratum of the local clock, when not synchronized through ntp. The default value of 16 is conventionally used to indicate unsynchronized clocks. This can be used in servers to indicate that there are external mechanisms synchronizing the clock by setting it to the appropriate value for the external source. If the external source is a GPS clock or a direct connection to a UTC source, this will typically be 1. |
| poll-interval-limits | { min = 4, max = 10 } | Limits on the poll interval towards clients. The defaults are fine for most applications. The values are given as the log2 of the number of seconds, so 4 indicates a poll interval of 32 seconds, and 10 a poll interval of 1024 seconds. |
| initial-poll | 4 | Initial poll interval used on startup. The value is given as the log2 of the number of seconds, so 4 indicates a poll interval of 32 seconds. |

For panic thresholds, asymmetric thresholds can be configured, allowing a different sized step going forwards compared to going backwards. This is done by configuring a struct with two values, `forward` and `backward` for the panic threshold.

##### Algorithm specific options

NTPD-rs currently supports two choices for algorithms:
 - A custom, high performance algorithm.
 - The algorithm specified in RFC5905

Which algorithm is used is determined by a compile time flag (see above).

The high performance clock algorithm has quite a few options. Most of these are quite straightforward to understand and can be used to tune the style of time synchronization to the users liking (although the defaults are probably fine for most):
| Option | Default | Description |
| --- | --- | --- |
| steer-offset-threshold | 2.0 | How far from 0 (in multiples of the uncertainty) should the offset be before we correct. A higher value reduces the amount of steering, but at the cost of a slower synchronization. (standard deviations, 0+) |
| steer-offset-leftover | 1.0 | How many standard deviations do we leave after offset correction? A higher value decreases the amount of overcorrections at the cost of slower synchronization and more steering. (standard deviations, 0+) |
| jump-threshold | 10e-3 | From what offset should we jump the clock instead of trying to adjust gradually? (seconds, 0+) |
| slew-max-frequency-offset | 200e-6 | What is the maximum frequency offset during a slew (a gradual changing of the time). (s/s) |
| slew-min-duration | 20.0 | What is the minimum duration of a slew (a gradual changing of the time). Larger values increase the precision of the slew, at the cost of longer time taken per slew. (s) |
| steer-frequency-threshold | 2.0 | How far from 0 (in multiples of the uncertainty) should the frequency estimate be before we correct. A higher value reduces the amount of steering, but at the cost of a slower synchronization. (standard deviations, 0+) |
| steer-frequency-leftover | 1.0 | How many standard deviations do we leave after frequency correction? A higher value decreases the amount of overcorrections at the cost of slower synchronization and more steering. (standard deviations, 0+) |
| ignore-server-dispersion | false | Ignore a servers advertised dispersion when synchronizing. Can improve synchronization quality with servers reporting overly conservative root dispersion. |
| range-statistical-weight | 2.0 | Weight of statistical uncertainty when constructing a peers uncertainty range. This range is used when checking if two peers agree on the same time, and for choosing whether to use a peer for synchronization. (standard deviations, 0+) |
| range-delay-weight | 0.25 | Weight of delay uncertainty when constructing overlap ranges. This range is used when checking if two peers agree on the same time, and for choosing whether to use a peer for synchronization. (weight, 0-1) |
| max-peer-uncertainty | 1.0 | Maximum peer uncertainty before we start disregarding it. Note that this is combined uncertainty due to noise and possible asymmetry error (see also weights above). (seconds) |
| poll-jump-threshold | 1e-6 | Probability threshold for when a measurement is considered a significant enough outlier that we decide something weird is going on and we need to immediately decrease the polling interval to quickly correct. (probability, 0-1) |
| delay-outlier-threshold | 5.0 | Threshold (in number of standard deviations) above which measurements with a significantly larger network delay are rejected. (standard deviations, 0+) |
| initial-wander | 1e-8 | Initial estimate of the clock wander between our local clock and that of the peer. Increasing this results in better synchronization if the hardware matches it, but at the cost of slower synchronization when overly optimistic. (s/s^2) |
| initial-frequency-uncertainty | 100e-6 | Initial uncertainty of the frequency difference between our clock and that of the peer. Lower values increase the speed of frequency synchronization when correct, but decrease it when overly optimistic. (s/s) |

A second set of options control more internal details of how the algorithm estimates its errors and regulates the poll interval. Care should be taken in choosing the values here, and they are primarily provided for easy access when developing the algorithm further:
| Option | Default | Description |
| --- | --- | --- |
| precision-low-probability | 0.333 | Probability bound below which we start moving towards decreasing our precision estimate. (probability, 0-1) |
| precision-high-probability | 0.667 | Probability bound above which we start moving towards increasing our precision estimate. (probability, 0-1) |
| precision-hysteresis | 16 | Amount of hysteresis in changing the precision estimate. (count, 1+) |
| precision-min-weight | 0.1 | Lower bound on the amount of effect our precision estimate has on the total noise estimate before we allow decreasing of the precision estimate. (weight, 0-1) |
| poll-low-weight | 0.4 | Amount which a measurement contributes to the state, below which we start increasing the poll interval. (weight, 0-1) |
| poll-high-weight | 0.6 | Amount which a measurement contributes to the state, above which we start decreasing the poll interval. (weight, 0-1) |
| poll-hysteresis | 16 | Amount of hysteresis in changing the poll interval (count, 1+) |
| max-frequency-steer | 495e-6 | Maximum steering input to system clock. (s/s) |

The RFC algorithm has different options for tuning. All of these have reasonable defaults and care should be taken when changing them.
| Option | Default | Description |
| --- | --- | --- |
| min-cluster-survivors | 3 | Number of servers beyond which we do not try to exclude further servers for the purpose of improving measurement precision. Do not change unless familiar with the NTP algorithms. |
| frequency-tolerance | 15 | Estimate of the short-time frequency precision of the local clock, in parts-per-million. The default is usually a good approximation. |
| distance-threshold | 1 | Maximum delay to the clock representing ground truth via a peer for that peer to be considered acceptable, in seconds. |
| frequency-measurement-period | 900 | Amount of time to spend on startup measuring the frequency offset of the system clock, in seconds. Lowering this means the clock is kept actively synchronized sooner, but reduces the precision of the initial frequency estimate, which could result in lower stability of the clock early on. |
| spike-threshold | 900 | Amount of time before a clock difference larger than 125ms is considered real instead of a spike in the network. Lower values ensure large errors are corrected faster, but make the client more sensitive to network issues. Value provided is in seconds. |

#### Example configuration file:

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
poll-interval-limits = { min = 6, max = 10 }
panic-threshold = 10
startup-panic-threshold = { forward = "inf", backward = 1800 }
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
