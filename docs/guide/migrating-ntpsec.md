# Migrating from NTPsec

Both ntpsec and ntpd-rs can serve a similar role on Unix systems. This guide is aimed to help those migrating machines currently running ntpsec to ntpd-rs. We assume some experience with the [ntpsec configuration format](https://docs.ntpsec.org/latest/ntp_conf.html#_reference_clock_support). A user with no or little ntpsec experience may be better of following our [getting started guide](getting-started.md).

**Configuration format:** ntpsec uses a custom format that functions as a list of commands. In contrast, `ntpd-rs` uses a configuration file in the `.toml` format that gives values to properties. That means that in most cases fields cannot be repeated. Comments can be added by starting them with a `#`. The remainder of the line is then ignored.

**Defaults:** ntpsec and `ntpd-rs` may use different default values for some properties. When migrating, pay particular attention toml

* `minsane`/`minimum-agreeing-peers`
* `step/stepback/stepfwd`/`single-step-panic-threshold/startup-step-panic-threshold/accumulated-step-panic-threshold`
* NTS server functionality

`ntpd-rs` configuration can be validated with `ntp-ctl validate -c <path>`. This will check all field names, and in some cases validates that a value is within the range of valid values for that property.

This guide will not go into detail on all of ntpsec's configuration directives, but rather focus on those most important for successful migration. If a particular directive is not mentioned here, there may still be ntpd-rs options in the [configuration reference](../ntp.toml.5.md) that achieve the desired effect. Note that not all functionality of ntpsec is currently supported, a short overview of major differences is given [at the end of this document](#unsupported-features)

## Time sources

### Server entries

Client-server connections need to be migrated in one of two ways:

- As a simple peer, if no authentication is used.
- As an NTS peer, if NTS is enabled (i.e. the NTS option is present in the server directive).

For server entries with no authentication, these can be converted to
```
# ntpsec
server 0.pool.ntp.org
server 1.pool.ntp.org

# ntpd-rs
[[peer]]
mode = "simple"
address = "0.pool.ntp.org"

[[peer]]
mode = "simple"
address = "1.pool.ntp.org"
```

For server directives with NTS, these can be converted to
```
# ntpsec
server ntp.time.nl nts
server ntp.example.com nts ca path/to/certificate/authority.pem

# ntpd-rs
[[peer]]
mode="nts"
address="ntp.time.nl"

[[peer]]
mode="nts"
address="ntp.example.com"
certificate_authority = "path/to/certificate/authority.pem"
```

If the server directive contains poll limits (`maxpoll` or `minpoll`), these cannot be specified on a per-server basis in ntpd-rs. The best approach is to determine values acceptable for all time sources and apply these via peer defaults:
```
[peer-defaults]
poll-interval-limits = { min = <minpoll>, max = <maxpoll> }
initial-poll-interval = <desired initial poll interval>
```

There is no support for bursting in ntpd-rs yet. When any bursting directive (`burst` or `iburst`) is present, these usually can be ignored, although if custom poll limits are in place, these may need to be increased.

### Refclock directives

The current version of ntpd-rs unfortunately does not yet support local reference clocks. It is however currently on our roadmap. If you are interested in migrating a configuration using local reference clocks, we would be interested in hearing the details. This information will help guide our implementation effort.

## Time synchronization options

The minimum number of sources needed for time synchronization in ntpd-rs is configured through `minimum-agreeing-peers`:
```
[synchronization]
mininum-agreeing-peers = <minsources>
```
Note that although the effect of this option is the same as ntpsec's `minsane`, the default in ntpd-rs is 3, rather than the default 1 source required by ntpd. Although 3 is recommended for security, it may not be appropriate for all configurations, particularly configurations with few remote sources configured.

Through the `step/stepfwd/stepback/stepout` directives, ntpd allows limiting of the maximum change in time made. Although not entirely the same in functionality, ntpd-rs allows similar restrictions to be enforced through a number of panic thresholds. Steps at startup are controlled through the `startup-panic-threshold`, whilst steps during normal operation are controlled with `single-step-panic-threshold` and `accumulated-step-panic-threshold`. In contrast with ntpd, these do not allow ignoring of the first few occurrences, and more importantly, have finite default values:
```
[synchronization]
single-step-panic-threshold = 1000
startup-step-panic-threshold = { forward="inf", backward = 86400 }
accumulated-step-panic-threshold = "inf"
```

ntpsec and `ntpd-rs` use different algorithms for synchronizing the time. This means that options for tuning filtering of the time differ significantly, and we cannot offer precise guidance on how to translate the ntpsec parameters to values for `ntpd-rs`. When migrating a configuration that tunes ntpsec's algorithm, one should take the intent of the tuning and use that as guidance when choosing which [time synchronization options](../man/ntp.toml.5.md#synchronization) to change.

There is a major philosophical difference between ntpsec and ntpd-rs. For ntpsec, the majority of the algorithm tuning parameters are set on an individual time source. Within ntpd-rs, all control of the filtering is done via global parameters. Although we do not expect this to be the case, should there be specific parameters you would wish to configure on a per-peer basis, please let us know so we can consider this for future releases.

## Server configuration

Server configuration in ntpd-rs works quite a bit differently from ntpsec. Rather than enabling time server functionality by `allow`ing remote connections to the server, one or more serving instances can be individually configured. Each of these comes with its own allow and deny list:
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
The allow and deny list configuration is optional in ntpd-rs. By default, if a server is configured it will accept traffic from anywhere. When configuring both allow and deny lists, ntpd-rs will first check if a remote is on the deny list. Only if this is not the case will the allow list be considered. This needs to be taken into account when translating interleaved combinations of ntpsec's `allow` and `deny` commands.

NTS can be enabled for a server by simply configuring an NTS key exchange server:

```
# ntpsec
nts key /etc/letsencrypt/live/ntp.example.com/privkey.pem
nts cert /etc/letsencrypt/live/ntp.example.com/fullchain.pem

# ntpd-rs
[[nts-ke-server]]
key-exchange-listen = "<ip or [::]>:<port>
certificate-chain-path = "/etc/letsencrypt/live/ntp.example.com/fullchain.pem"
private-key-path = "/etc/letsencrypt/live/ntp.example.com/privkey.pem"
```

Note that unlike ntpsec, ntpd-rs does not have a default ip address on which it listens for nts-ke traffic, and this needs to be explicitly provided. The port is optional however and defaults to the standard value 4460.

The keys used to sign the cookies kept in memory, but can additionally be stored to a file (so they are preserved after a restart).

```
# ntpsec
nts cookie /var/lib/ntp/nts-keys

# ntpd-rs
[keyset]
key_storage_path = "/var/lib/ntp/nts-keys"
```

Note that in contrast to ntpsec's `cookie` option, here the full path needs to be specified, and there is no default path.

Rotation of the keys is by default daily, with one full week's worth of old keys remembered for serving clients with older cookies. This can be configured with the `key-rotation-interval` and `stale-key-count` parameters:
```
[keyset]
stale-key-count = <number of old keys to keep>
key-rotation-interval = <rotation interval in seconds>
```
Note that the defaults for these settings mean that cookies for the server are only valid for slightly more than 1 week. 

Sharing the keys with which the nts cookies are encrypted between multiple ntpd-rs servers is not yet supported.

The stratum can can be configured in ntpd-rs with the `local-stratum` key:
```
[synchronization]
local-stratum = <stratum>
```

Broadcast mode is not currently supported in ntpd-rs. If this is used in your current setup, configuring the ntp server via dhcp instead may be an alternative.

## Unsupported features

Not all functionality in ntpsec currently has an equivalent in ntpd-rs. In particular, the following major features currently don't have good alternatives in ntpd-rs:
- Local hardware devices as time sources.
- Support for ntp mac authentication.
- Marking subsets of sources as more trusted than others.
- Acting as a source of leap second data.
- protocol modes beside server and client
- bursting
If any of these features are critical for your use case, ntpd-rs might not be an option for you yet. Please let us know if you miss these features or want to sponsor any of them, as this helps us prioritise our work.
