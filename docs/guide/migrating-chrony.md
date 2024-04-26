# Migrating from chrony

Both chrony and ntpd-rs can serve a similar role on Unix systems. This guide aims to help those migrating machines currently running chrony to ntpd-rs. We assume some experience with the [chrony configuration format](https://chrony-project.org/doc/4.3/chrony.conf.html). A user with no or little chrony experience may be better off following our [getting started guide](getting-started.md).

Before we start with the specifics on how to convert individual directives, first a few notes. In contrast with the chrony configuration format, which acts like a list of commands to the client, the ntpd-rs configuration is a [TOML](https://toml.io/) file. In particular, this means configuration is done by giving values for properties. As such, fields cannot be repeated unless they are part of a list, such as with the `[[source]]` sections and `[[server]]` sections. Comments can be added by starting them with a `#`. The remainder of the line is then ignored.

Please note that for some of the settings below, ntpd-rs and chrony use different defaults. When converting a configuration, please pay particular attention to `minsources`/`minimum-agreeing-sources`, `maxstep` and the corresponding `-panic-thresholds`, and any settings for NTS server functionality. Validation of the resulting ntpd-rs configuration can be done with `ntp-ctl validate -c <path>`, which should at least catch the most egregious errors.

This guide does not go into detail on all of chrony's configuration directives, but rather focusses on those most important for successful migration. If a directive is not mentioned here, there may still be ntpd-rs options in the [configuration reference](../man/ntp.toml.5.md) that achieve the desired effect. Note that not all functionality of chrony is currently supported, a short overview of major differences is given [at the end of this document](#non-supported-features)

## Time sources

### Server directives

Client-server connections need to be migrated in one of two ways:
- As a server source, if no authentication is used.
- As an NTS source, if NTS is enabled (i.e. the NTS option is present in the server directive).

For server directives with no authentication, these can be converted to
```toml
[[source]]
mode="server"
address="<address>"
```
where the address is the same as that given in the server directive.

For server directives with NTS, these can be converted to
```toml
[[source]]
mode="nts"
address="<address>"
```

If the server directive contains poll limits (`maxpoll` or `minpoll`), these cannot be specified on a per-server basis in ntpd-rs. The best approach is to determine values acceptable for all time sources and apply these via source defaults:
```toml
[source-defaults]
poll-interval-limits = { min = <minpoll>, max = <maxpoll> }
initial-poll-interval = <desired initial poll interval>
```

There is no support for bursting in ntpd-rs yet. When any bursting directive (`burst` or `iburst`) is present, these usually can be ignored, although if custom poll limits are in place, these may need to be rethought.

For NTS, if a custom certificate set is configured for a source via the `certset` directive, these can be provided via the ntpd-rs `certificate_authority` option. This expects a path to a file containing all the accepted root certificates for the source accepted in addition to the system certificates.

### Pool directives

Pools configured via the pool directive can be added to the ntpd-rs configuration via
```toml
[[pool]]
mode="pool"
address="<address>"
```

If the pool directive specifies `maxsources`, this value can be configured in ntpd-rs via the `count` property. The default (4) is the same between ntpd-rs and chrony.

If the pool directive contains poll limits (`maxpoll` or `minpoll`), these cannot be specified on a per-server basis in ntpd-rs. The best approach is to determine values acceptable for all time sources and apply these via source defaults:
```toml
[source-defaults]
poll-interval-limits = { min = <minpoll>, max = <maxpoll> }
initial-poll-interval = <desired initial poll interval>
```

There is currently no support for bursting in ntpd-rs. When any bursting option (`burst` or `iburst`) is present, these usually can be ignored, although if custom poll limits are in place, these may need to be relaxed.

### Time source directives

Symmetric peer modes are not supported in ntpd-rs, and are unlikely to be supported in the future. When migrating a configuration with symmetric peer connections, we recommend replacing these with client-server mode connections on both clients (see also [Server directives](#server-directives) above).

### Refclock directives

The current version of ntpd-rs does not yet support local reference clocks, but this feature is on our roadmap. If you are interested in migrating a configuration using local reference clocks, we would be interested in hearing the details. This information can help guide our implementation effort.

## Time synchronization options

The minimum number of sources needed for time synchronization in ntpd-rs is configured through `minimum-agreeing-sources`:
```toml
[synchronization]
mininum-agreeing-sources = <minsources>
```
Note that although the effect of this option is the same as chrony's `minsources`, the default in ntpd-rs is 3, rather than the default 1 source required by chrony. Although 3 is recommended for security, it may not be appropriate for all configurations, particularly configurations where few remote sources are configured.

Chrony can limit the maximum time change with the `maxchange` directive. ntpd-rs allows similar restrictions to be enforced through a number of panic thresholds. Steps at startup are controlled through the `startup-panic-threshold`, whilst steps during normal operation are controlled with `single-step-panic-threshold` and `accumulated-step-panic-threshold`. In contrast to chrony, these do not allow ignoring of the first few occurrences, and more importantly, have finite default values:
```toml
[synchronization]
single-step-panic-threshold = 1000
startup-step-panic-threshold = { forward="inf", backward = 86400 }
accumulated-step-panic-threshold = "inf"
```

Chrony and ntpd-rs use different algorithms for synchronizing the time. This means that options for tuning filtering of the time differ significantly, and we cannot offer precise guidance on how to translate the chrony parameters to values for ntpd-rs. When migrating a configuration that tunes chrony's algorithm, one should take the intent of the tuning and use that as guidance when choosing which [time synchronization options](../man/ntp.toml.5.md#synchronization) to change.

When tuning the synchronization algorithm, it is important to note a major philosophical difference between chrony and ntpd-rs. For chrony, the majority of the algorithm tuning parameters are set on an individual time source. Within ntpd-rs, all control of the filtering is done via global parameters. Although we do not expect this to be the case, should there be specific parameters you would wish to configure on a per-source basis, please let us know so we can consider this for future releases.

## Server configuration

Server configuration in ntpd-rs works quite a bit differently from chrony. Rather than enabling time server functionality by `allow`ing remote connections to the server, one or more serving instances can be individually configured. Each of these comes with its own allow and deny list.
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

The allow and deny list configuration is optional in ntpd-rs. By default, a server accepts traffic from anywhere. When configuring both allow and deny lists, ntpd-rs will first check if a remote is on the deny list. Only if this is not the case will the allow list be considered. This ordering needs to be taken into account when translating interleaved combinations of chrony's `allow` and `deny` commands.

NTS can be enabled for a server by configuring an NTS key exchange server:
```toml
[[nts-ke-server]]
listen = "<IP or [::]>:4460"
certificate-chain-path = <ntsservercert>
private-key-path = <ntsserverkey>
```
Here the names of the corresponding chrony directives are used on the right hand side of the assignment. Note that unlike chrony, ntpd-rs does not have a default IP address on which it listens for nts-ke traffic: this need to be provided explicitly. The port is optional however and defaults to the standard value 4460.

The keys used to encrypt the cookies are ephemeral by default. If these should be kept across reboots of the server, the path for storing these can be configured:
```toml
[keyset]
key-storage-path = <path to key storage>
```
Note that in contrast to chrony's `ntsdumpdir` directive, here the full path needs to be specified, and there is no default path.

The default key rotation interval is daily, and one full week's worth of old keys is retained for serving clients with older cookies.
With these defaults, cookies for the server are only valid for slightly more than one week. This is much less than chrony's default of 3 weeks.
These settings can be configured with the `key-rotation-interval` and `stale-key-count` parameters:
```toml
[keyset]
stale-key-count = <number of old keys to keep>
key-rotation-interval = <rotation interval in seconds>
```

Sharing the keys with which the NTS cookies are encrypted between multiple ntpd-rs servers is not yet supported.

If a local stratum for the server is configured through `local stratum`, this can be configured in ntpd-rs through the `local-stratum` key:
```toml
[synchronization]
local-stratum = <stratum>
```

Broadcast mode is not supported in ntpd-rs. If this is used in your current setup, configuring the NTP server via DHCP instead may be an alternative. Note that using broadcast mode may leave you more vulnerable to security issues.

## Non-supported features

Not all functionality in chrony currently has an equivalent in ntpd-rs. In particular, the following major features currently don't have good alternatives in ntpd-rs:

- Local hardware devices as time sources.
- Support for ntp mac authentication.
- Marking subsets of sources as more trusted than others.
- Acting as a source of leap second data.

If any of these features are critical for your use case, ntpd-rs might not be an option for you yet. Please let us know if you miss these features or want to sponsor any of them, as this helps us prioritise our work.
