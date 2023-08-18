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

```sh
#!/bin/sh

. /etc/rc.subr

# PROVIDE: ntp_daemon
# REQUIRE: DAEMON FILESYSTEMS devfs
# BEFORE:  LOGIN
# KEYWORD: nojail resume shutdown

name="ntp_daemon"
rcvar="ntp_daemon_enable"

: ${ntp_daemon_enable:="NO"}

start_precmd="${name}_precmd"

command="/usr/sbin/daemon"
procname="ntp-daemon"
pidfile="/var/run/${name}.pid"
command_args=" -f -o /var/log/ntp_daemon.log -H -P ${pidfile} /usr/local/bin/ntp-daemon --"

load_rc_config $name
run_rc_command "$1"
```
