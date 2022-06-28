# Management Client

NTPD-rs comes with a management client for the daemon. This client can show the current state of the daemon, as well as change the log level and panic thresholds of the daemon.

## Enabling the management client

In order to communicate with the daemon, the management client relies on two sockets, an observation socket and a configuration socket, which are disabled by default. To enable use of the client, these sockets should be enabled in [the configuration](CONFIGURATION.md). On Linux, it is common to place these sockets in a subdirectory of `/run` specific to the daemon.

The client can run with only one of the sockets enabled. In that situation, not all functionality is available. The same holds when the currently running user has insufficient permissions for one of the sockets.

For the configuration socket, default permissions restrict access to the group under which the server is running. Users should be added to this group when they need to be able to change configuration settings of the daemon dynamically.

## Using the management client

The current client exposes 3 different commands:
 - `ntp-client peers` displays information on the currently active peer connections
 - `ntp-client system` displays information on the current synchronization state of the system.
 - `ntp-client config` allows changing of some configuration parameters

## Available configuration parameters

Currently, only the `log-level` and `panic-threshold` configuration parameters can be set dynamically, through the `--log-level` and `--panic-threshold` command line parameters respectively. For information on the allowed values for these, see [the configuration documentation](CONFIGURATION.md).

## Specifying socket locations

By default, the management client looks for the daemons configuration either in `./ntp.toml` or `/etc/ntp.toml` in order to extract the paths of the socket. If neither of these are present, or when the socket paths are not configured in these, it defaults to `/run/ntpd-rs/observe` for the observation socket and `/run/ntpd-rs/configure` for the configuration sockets.

If the client fails to find the correct socket paths using the above process, it can be manually configured to look elsewhere. Most advisable is to point the management client to the configuration file of the server via the `--config` command line flag. If this is not an option in your setup, alternatively the `--observation-socket` and `--configuration-socket` command line options.
