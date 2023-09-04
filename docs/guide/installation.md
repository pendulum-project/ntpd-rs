# Installation

## Installers & Packages

The recommended way of installing ntpd-rs is through an installer or package manager for your system.

### Linux

We recommend the installers from our [installation page](https://github.com/pendulum-project/ntpd-rs/releases). The installer takes care of putting the configuration in the right place and setting up the recommended users and permissions. The default configuration file is located at `/etc/ntpd-rs/ntp.toml`

## FreeBSD

The ntpd-rs binary is available on [ports](https://www.freshports.org/net/ntpd-rs/). The default configuration file is located at `%%ETCDIR%%/ntp.toml`, which typically resolves to `/etc/ntp.toml`.

## macOS

There is no package or installer for macOS at the moment.

## Install From Source

On platforms without an installer or package, building from source is an option.
ntpd-rs is written in rust. We strongly recommend using [rustup] to install a
rust toolchain, because the version provided by system package managers tends to
be out of date. Be sure to use a recent version of the rust compiler. To build
ntpd-rs run

```sh
cargo build --release
```

This produces a `ntp-daemon` binary at `target/release/ntp-daemon`, which is the
main NTP daemon. Expected output looks like this:

```
> sudo target/release/ntp-daemon -c pkg/common/ntp.toml.default
2023-09-04T12:01:44.055104Z  WARN ntpd::daemon::observer: Abnormal termination of the state observer: Could not create observe socket at "/run/ntpd-rs/observe" because its parent directory does not exist
2023-09-04T12:01:44.055183Z  WARN ntpd::daemon::observer: The state observer will not be available
2023-09-04T12:01:44.071353Z  INFO ntpd::daemon::system: new peer source_id=PeerId(1) addr=185.172.91.110:123 spawner=SpawnerId(1)
2023-09-04T12:01:44.071735Z  INFO ntpd::daemon::system: new peer source_id=PeerId(2) addr=162.159.200.1:123 spawner=SpawnerId(1)
2023-09-04T12:01:44.071944Z  INFO ntpd::daemon::system: new peer source_id=PeerId(3) addr=45.138.55.62:123 spawner=SpawnerId(1)
2023-09-04T12:01:44.072150Z  INFO ntpd::daemon::system: new peer source_id=PeerId(4) addr=213.154.236.182:123 spawner=SpawnerId(1)
2023-09-04T12:01:44.084626Z  INFO ntp_proto::algorithm::kalman: No concensus cluster found
2023-09-04T12:01:44.085422Z  INFO ntp_proto::algorithm::kalman: No concensus cluster found
2023-09-04T12:01:44.086879Z  INFO ntp_proto::algorithm::kalman: Offset: 2.3686082232975885+-72.6249392570874ms, frequency: 0+-5773502.691896258ppm
2023-09-04T12:01:44.087846Z  INFO ntp_proto::algorithm::kalman: Offset: 2.7204471636925773+-61.339759726948046ms, frequency: 0+-5000000.000000001ppm
```

To use this binary as your system NTP daemon, some setup is required:

- move to `ntp-daemon` binary to an appropriate location (e.g. `/usr/bin`)
- create the path for the observe socket
- permissions for the binary, config files and observe socket

Then you must configure ntpd-rs as a system service.

### Running as a system service


It is by far the easiest to have your operating system and standard tools take care of the details like:

- ensure that no competing NTP daemon is running
- ensure that the daemon is started on startup
- handling the ntpd-rs logs 

Below are configurations for linux (using `SystemD`) and FreeBSD (using a .rc file).

#### Linux + SystemD

This is the SystemD configuration used by the ntpd-rs linux installer.

```ini
[Unit]
Description=Rust Network Time Service
Documentation=https://github.com/pendulum-project/ntpd-rs
After=network-online.target
Wants=network-online.target
Conflicts=systemd-timesyncd.service ntp.service chrony.service

[Service]
Type=simple
Restart=no
ExecStart=/usr/local/bin/ntp-daemon
Environment="RUST_LOG=info"
RuntimeDirectory=ntpd-rs
User=ntpd-rs
Group=ntpd-rs
AmbientCapabilities=CAP_SYS_TIME
# Note: when running a server on the default port 123, permissions to bind to
# low (<1024) ports is also needed, which can be given with
# AmbientCapabilities=CAP_SYS_TIME CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

#### FreeBSD

This is the [rc script](https://github.com/freebsd/freebsd-ports/blob/main/net/ntpd-rs/files/ntp_daemon.in) used by the FreeBSD port of ntpd-rs.

```sh
#!/bin/sh

# PROVIDE: ntp_daemon
# REQUIRE: DAEMON FILESYSTEMS devfs
# BEFORE:  LOGIN
# KEYWORD: nojail resume shutdown
#
. /etc/rc.subr

name=ntp_daemon
rcvar=ntp_daemon_enable

load_rc_config $name

ntp_daemon_enable=${ntp_daemon_enable-"NO"}
ntp_daemon_config=${ntp_daemon_config-"%%ETCDIR%%/ntp.toml"}
ntp_daemon_socket=${ntp_daemon_socket-"/var/run/ntpd-rs"}

command="/usr/bin/true"
procname="/usr/sbin/daemon"
pidfile="/var/run/${name}.pid"

start_cmd="ntp_daemon_start"
stop_cmd="ntp_daemon_stop"

is_process_running()
{
	[ -f ${pidfile} ] && procstat $(cat ${pidfile}) >/dev/null 2>&1
}

ntp_daemon_start()
{
	[ -d "${ntp_daemon_socket}" ] || /bin/mkdir "${ntp_daemon_socket}"
	/usr/sbin/chown _ntp:_ntp "${ntp_daemon_socket}"
	/usr/sbin/daemon -P ${pidfile} -r -f -o /var/log/ntp_daemon.log -H %%PREFIX%%/bin/ntp-daemon --config "${ntp_daemon_config}"

	if is_process_running; then
		echo "Started ntp-daemon (pid=$(cat ${pidfile}))"
	else
		echo "Failed to start ntp-daemon"
	fi
}

ntp_daemon_stop()
{
	if is_process_running; then
		/bin/rm -rf "${ntp_daemon_socket}"
		local pid=$(cat ${pidfile})
		echo "Stopping ntp-daemon (pid=${pid})"
		kill -- -${pid}
	else
		echo "ntp-daemon isn't running"
	fi
}

run_rc_command "$1"
```

[rustup]: https://rustup.rs
