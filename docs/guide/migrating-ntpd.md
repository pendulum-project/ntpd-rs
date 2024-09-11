# Migrating from ntpd

Both [ntpd](https://www.ntp.org/), the NTP reference implementation, and ntpd-rs can serve a similar role on Unix systems. This is a guide for converting a ntpd configuration into a ntpd-rs configuration. We assume some experience with the [ntpd configuration format](https://www.ntp.org/documentation/4.2.8-series/comdex/). A user with no or little ntpd experience may be better of following our [getting started guide](getting-started.md).

Configuration for ntpd uses a custom format that functions as a list of commands. In contrast, ntpd-rs uses a configuration file in the `.toml` format that gives values to properties. That means that in most cases fields cannot be repeated. Comments can be added by starting them with a `#`. The remainder of the line is then ignored.

An `ntpd-rs` configuration can be validated with `ntp-ctl validate -c <path>`. This will check all field names, and in some cases validates that a value is within the range of valid values for that property.

This guide will not go into detail on all of ntpd's configuration directives, but rather focus on those most important for successful migration. If a particular directive is not mentioned here, there may still be ntpd-rs options in the [configuration reference](../man/ntp.toml.5.md) that achieve the desired effect. Note that not all functionality of ntpd is currently supported, a short overview of major differences is given [at the end of this document](#unsupported-features).

## Time sources

The `server` and `pool` commands have a direct equivalent in ntpd-rs:

```toml
# ntpd
server 0.pool.ntp.org
server 1.pool.ntp.org
pool pool.ntp.org

# ntpd-rs
[[source]]
mode = "server"
address = "0.pool.ntp.org"

[[source]]
mode = "server"
address = "1.pool.ntp.org"

[[source]]
mode = "pool"
address = "pool.ntp.org"
count = 4
```

A source in `pool` mode must explicitly define an integer `count`, the maximum number of connections from this pool. The ntpd-rs daemon will actively try to keep the pool "filled": new connections will be spun up if a source from the pool is unreachable.

The symmetric and broadcasting association modes are deliberately not supported in ntpd-rs because these modes have security issues. The `peer` command can be substituted with a standard `server` source. For the `broadcast` command, configuring the NTP server via DHCP instead may be an alternative

There is no direct equivalent of ntpd's `maxpoll` and `minpoll` flags that can be configured on a per-source basis. Instead ntpd-rs defines poll interval bounds globally for all time sources:
```toml
[source-defaults]
poll-interval-limits = { min = <minpoll>, max = <maxpoll> }
initial-poll-interval = <desired initial poll interval>
```

There is no support for bursting in ntpd-rs yet, but the ntpd-rs algorithm is able to synchronize much more quickly (with fewer measurements) than ntpd's algorithm. Therefore, if any bursting directive (`burst` or `iburst`) is present, these usually can be ignored when translating configurations. In some cases, if strict custom poll limits are in place, these may need to be relaxed.

### Reference clocks

The current version of ntpd-rs does not yet support local reference clocks, but this feature is on our roadmap. If you are interested in migrating a configuration using local reference clocks, we would be interested in hearing the details. This information will help guide our implementation effort.

## Time synchronization options

The minimum number of time sources needed for time synchronization in ntpd-rs is configured through `minimum-agreeing-sources`:
```toml
[synchronization]
minimum-agreeing-sources = <minsources>
```
If fewer agreeing source are available, no synchronization is performed and the clock will drift. This option is a combination of ntpd's `minclock` and `minsane`. Its default value is 3, the recommended value from a security perspective. In ntpd, a default of 3 is used for `minclock` and 1 for `minsane`.

Through the `tinker` command's `step` and `stepout` flags, ntpd allows limiting of the maximum change in time made. Although not entirely the same in functionality, ntpd-rs allows similar restrictions to be enforced through a number of panic thresholds. Steps at startup are controlled through the `startup-panic-threshold`, whilst steps during normal operation are controlled with `single-step-panic-threshold` and `accumulated-step-panic-threshold`.
```toml
[synchronization]
single-step-panic-threshold = 1000
startup-step-panic-threshold = { forward="inf", backward = 86400 }
accumulated-step-panic-threshold = "inf"
```

ntpd and ntpd-rs use different algorithms for synchronizing the time. This means that options for tuning filtering of the time differ significantly, and we cannot offer precise guidance on how to translate the ntpd parameters to values for ntpd-rs. When migrating a configuration that tunes ntpd's algorithm, one should take the intent of the tuning and use that as guidance when choosing which of ntpd-rs's [time synchronization options](../man/ntp.toml.5.md#synchronization) to change.

## Server Configuration & Access Control

The [`restrict` command](https://www.ntp.org/documentation/4.2.8-series/accopt/) is used in ntpd to deny requests from a client. In ntpd this is a global setting. A flag configures what happens with connections from this client. For instance, `ignore` will silently ignore the request, while `kod` sends a response to the client that notifies it that its request is denied.

This logic is expressed differently in ntpd-rs. A specific server can be configured to have a `denylist` and an `allowlist`.
The subnets to allow or deny must be specified in CIDR notation
(an IP address followed by a slash and the number of masked bits, for example `127.0.0.1/8` or `192.168.1.1/24`)

```toml
[[server]]
listen="<ip or [::]>:<port>"

[server.allowlist]
filter = [
    "<subnet1>",
    "<subnet2>",
]
action = "ignore"

[server.denylist]
filter = [
    "<subnet3>",
    "<subnet4>",
]
action = "deny"
```

The allow and deny list configurations are both optional in ntpd-rs. By default, if a server is configured it will accept traffic from anywhere. When configuring both allow and deny lists, ntpd-rs will first check if a remote is on the deny list. Only if this is not the case will the allow list be considered.

The `allowlist.action` and `denylist.action` properties can have two values:

- `ignore` corresponds to ntpd's `ignore` and silently ignores the request
- `deny` corresponds to ntpd's `kod` and sends a deny kiss-o'-death packet

The stratum can can be configured in ntpd-rs with the `local-stratum` key:
```toml
[synchronization]
local-stratum = <stratum>
```

## Unsupported features

Not all functionality in ntpd currently has an equivalent in ntpd-rs. In particular, the following major features currently don't have good alternatives in ntpd-rs:

- Local hardware devices as time sources.
- Support for ntp mac authentication.
- Marking subsets of sources as more trusted than others
- protocol modes beside server and client
- bursting
If any of these features are critical for your use case, ntpd-rs might not be an option for you yet. Please let us know if you miss these features or want to sponsor any of them, as this helps us prioritise our work.
