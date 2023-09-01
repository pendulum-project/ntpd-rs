# Installation

## Linux 

We recommend the installers from our [installation page](https://github.com/pendulum-project/ntpd-rs/releases). The installer takes care of putting the configuration in the right place and setting up the recommended users and permissions. The default configuration file is located at `/etc/ntpd-rs/ntp.toml`

## FreeBSD

The ntpd-rs binary is available on [ports](https://www.freshports.org/net/ntpd-rs/). Configuration is still a manual process. These are the steps we use:

For an example `rc.d` config file, see [here](../examples/run-as-service.md).

```sh
# Create a ntpd-rs config
cp ntp.toml /etc/ntpd-rs/ntp.toml

# Copy ntpd-rs rc.d config
cp ntp_daemon /etc/rc.d/ntp_daemon
chmod 755 /etc/rc.d/ntp_daemon

# Disable legacy ntp
sysrc ntpd_enable=NO

# Set boot for ntp_daemon service
sysrc ntp_daemon_enable=YES

# restart the ntp_daemon service
service ntp_daemon stop
service ntp_daemon start
```

This [issue](https://github.com/pendulum-project/ntpd-rs/pull/766) is where we prototyped deployment of FreeBSD. It may contain helpful information.

## macOS

We do not currently have installation guidelines for macOS.
