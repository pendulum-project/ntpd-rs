# Running as a system service

## Linux - SystemD

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

## FreeBSD

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
