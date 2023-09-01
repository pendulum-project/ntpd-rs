# Migrating from ntpd

Both ntpd, the NTP reference implementation, and ntpd-rs can serve a similar role on Unix systems. This is a guide for converting a ntpd configuration into a ntpd-rs configuration. We assume some experience with the [ntp configuration format](http://www.ntp.org/documentation/4.2.8-series/confopt/). A user with no or little ntpd experience may be better of following our [getting started guide](getting-started.md).

**Configuration format:** ntpd uses a custom format that functions as a list of commands. In contrast, ntpd-rs uses a configuration file in the `.toml` format that gives values to properties. That means that in most cases fields cannot be repeated. Comments can be added by starting them with a `#`. The remainder of the line is then ignored.

**Defaults:** ntpd and `ntpd-rs` may use different default values for some properties. When migrating, pay particular attention to:

* `minsane`/`minimum-agreeing-peers`
* `step/stepback/stepfwd`/`single-step-panic-threshold/startup-step-panic-threshold/accumulated-step-panic-threshold`

`ntpd-rs` configuration can be validated with `ntp-ctl validate -c <path>`. This will check all field names, and in some cases validates that a value is within the range of valid values for that property.

This guide will not go into detail on all of ntpd's configuration directives, but rather focus on those most important for successful migration. If a particular directive is not mentioned here, there may still be ntpd-rs options in the [configuration reference](../ntp.toml.5.md) that achieve the desired effect. Note that not all functionality of ntpd is currently supported, a short overview of major differences is given [at the end of this document](#unsupported-features)

## Time sources

The `server` and `pool` commands have an equivalent in ntpd-rs

```
# ntpd
server 0.pool.ntp.org
server 1.pool.ntp.org
pool pool.ntp.org

# ntpd-rs
[[source]]
mode = "simple"
address = "0.pool.ntp.org"

[[source]]
mode = "simple"
address = "1.pool.ntp.org"

[[source]]
mode = "pool"
address = "pool.ntp.org"
count = 4
```

A source in `pool` mode explicitly give define a `<count>`, the maximum number of connections from this pool. The ntpd-rs daemon will actively try to keep the pool "filled": new connections will be spun up if a source from the pool is unreachable.

There is no direct equivalent of `maxpoll` and `minpoll` that can be configured on a per-source basis. Instead ntpd-rs defines these properties globally for all time sources:
```
[source-defaults]
poll-interval-limits = { min = <minpoll>, max = <maxpoll> }
initial-poll-interval = <desired initial poll interval>
```

There is no support for bursting in ntpd-rs yet. When any bursting directive (`burst` or `iburst`) is present, these usually can be ignored, although if custom poll limits are in place, these may need to be relaxed.

### Peer directives

Symmetric peer modes are not supported in ntpd-rs, and are unlikely to be supported in the future. When migrating a configuration with symmetric peer connections, we recommend replacing these with client-server mode connections on both clients (see also [Server directives](#server-entries) above).

### Refclock directives

The current version of ntpd-rs unfortunately does not yet support local reference clocks. It is however currently on our roadmap. If you are interested in migrating a configuration using local reference clocks, we would be interested in hearing the details. This information will help guide our implementation effort.

## Time synchronization options

The minimum number of sources needed for time synchronization in ntpd-rs is configured through `minimum-agreeing-peers`:
```
[synchronization]
mininum-agreeing-peers = <minsources>
```
Note that although the effect of this option is the same as ntpd's `minsane`, the default in ntpd-rs is 3, rather than the default 1 source required by ntpd. Although 3 is recommended for security, it may not be appropriate for all configurations, particularly configurations with few remote sources configured.

Through the `step/stepfwd/stepback/stepout` directives, ntpd allows limiting of the maximum change in time made. Although not entirely the same in functionality, ntpd-rs allows similar restrictions to be enforced through a number of panic thresholds. Steps at startup are controlled through the `startup-panic-threshold`, whilst steps during normal operation are controlled with `single-step-panic-threshold` and `accumulated-step-panic-threshold`. In contrast with ntpd, these do not allow ignoring of the first few occurrences, and more importantly, have finite default values:
```
[synchronization]
single-step-panic-threshold = 1000
startup-step-panic-threshold = { forward="inf", backward = 86400 }
accumulated-step-panic-threshold = "inf"
```

ntpd and `ntpd-rs` use different algorithms for synchronizing the time. This means that options for tuning filtering of the time differ significantly, and we cannot offer precise guidance on how to translate the ntpd parameters to values for `ntpd-rs`. When migrating a configuration that tunes ntpd's algorithm, one should take the intent of the tuning and use that as guidance when choosing which [time synchronization options](../man/ntp.toml.5.md#synchronization) to change.

There is a major philosophical difference between ntpd and ntpd-rs. For ntpd, the majority of the algorithm tuning parameters are set on an individual time source. Within ntpd-rs, all control of the filtering is done via global parameters. Although we do not expect this to be the case, should there be specific parameters you would wish to configure on a per-peer basis, please let us know so we can consider this for future releases.

## Access Control

The [`restrict` command](https://www.ntp.org/documentation/4.2.8-series/accopt/) is used in ntpd to deny requests from a client. In ntpd this is a global setting. A flag configures what happens with connections from this client. For instance, `ignore` will silently ignore the request, while `kod` sends a response to the client that notifies it that its request is denied.

This logic is expressed differently in ntpd-rs. A specific server can be configured to have a `denylist` and an `allowlist`.

```
[[server]]
listen="<ip or [::]>:<port>"
allowlist = [
    <subnet1>,
    <subnet2>
]
allowlist-action = `ignore`
denylist = [
    <subnet3>,
    <subnet4>
]
denylist-action = `deny`
```
The allow and deny list configuration is optional in ntpd-rs. By default, if a server is configured it will accept traffic from anywhere. When configuring both allow and deny lists, ntpd-rs will first check if a remote is on the deny list. Only if this is not the case will the allow list be considered.

The `allowlist-action` and `denylist-action` properties can have two values:

- `ignore` corresponds to ntpd's `ignore` and silently ignores the request
- `deny` corresponds to ntpd's `kod` and sends a deny kiss-o'-death packet

## Unsupported features

Not all functionality in ntpd currently has an equivalent in ntpd-rs. In particular, the following major features currently don't have good alternatives in ntpd-rs:
- Local hardware devices as time sources.
- Support for ntp mac authentication.
- Marking subsets of sources as more trusted than others.
- Acting as a source of leap second data.
- protocol modes beside server and client
- bursting
If any of these features are critical for your use case, ntpd-rs might not be an option for you yet. Please let us know if you miss these features or want to sponsor any of them, as this helps us prioritise our work.
