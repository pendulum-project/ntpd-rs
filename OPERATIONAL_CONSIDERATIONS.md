# Operational considerations

When configuring ntpd-rs as the system NTP client, there are a number of security and availability related topics that need to be carefully considered. Most of these are not specific to ntpd-rs, but will apply to the configuration of any NTP client. Here, we will give a basic overview of these topics and our current recommendations.

## Required number of available servers

In its operation, NTP requires that a majority of the used servers agree (up to the precision of the measurements) on the current time. However, in this mechanism, any servers that are currently unavailable because of connection issues and the like are completely ignored. As a consequences, the required quorum of agreeing servers may be lower than expected.

To combat this, ntpd-rs provides the `min-intersection-survivors` setting to set a minimum number of servers that need to agree on the best time. Incrementing this beyond the default value of `3` decreases the likelihood of a bad server adversely affecting the system time. However, larger values also require a larger number of servers to be available before actively starting to synchronize the clock, potentially reducing availability.

The NTPv4 standard recommends using a value of at least `3` for `min-intersection-survivors`. When using this recommendation, it is important to configure enough remote servers to ensure the probability of dipping below `3` available servers is low enough.

## Maximum clock adjustment boundaries

Although no clock is perfect, a normally functioning wall-time clock in a computer will typically require only relatively small adjustments to stay synchronized to an external clock. As such, it may be desirable to limit the maximum allowed adjustment to the system clock in order to limit the impact of malicious or erroneous servers. ntpd-rs has two options available for this, `panic-threshold` and `startup-panic-threshold`.

The `panic-threshold` indicates the maximum amount ntpd-rs will adjust the system clock in a single step during normal operations. By default, this is limited to 30 minutes, but this may be lowered in the configuration. If an adjustment larger than `panic-threshold` is needed, NTD-rs will throw an error (panic). We advise human intervention in this case: automatically restarting ntpd-rs may cause a panic loop.

The `startup-panic-threshold` indicates the maximum amount ntpd-rs will adjust the system clock whilst starting up. Because the system may or may not have a hardware backup to use to keep time when shut down, the initial error of the system clock can be significantly larger than what can reasonably occur during normal operations. Therefore, this setting by default imposes no limit. Like `panic-threshold`, if `startup-panic-threshold` is set and exceeded, NTD-rs will throw an error (panic). We advise human intervention in this case: automatically restarting ntpd-rs may cause a panic loop.

Both the `panic-threshold` and `startup-panic-threshold` should be adjusted to achieve the desired mix of availability (avoiding false alarms) and resilience against erroneous servers.

## Automatic rebooting of the daemon

When ntpd-rs detects abnormal conditions during operation, it will automatically shut down. This is done to avoid poorly steering the clock and potentially inducing large clock errors, as once synchronized, an unsteered clock will keep time better than an actively incorrectly steered clock.

The abnormal conditions resulting in a shutdown include:
 - Detection of an abnormally large correction being required.
 - Detection of an inconsistent internal state.
 - Errors whilst trying to adjust the system clock.

We strongly recommend against automatically restarting the daemon when it exits, as doing so may cause additional incorrect steering of the system clock, resulting in a larger error against UTC than intended. Instead, a human operator should determine the root cause of the shutdown and decide on the proper corrective action to take.

Should it really be desirable to restart the daemon under certain circumstances (such as when killed by the Linux out-of-memory killer), this automatic restart should be configured as restrictive as possible, so as not to trigger outside the intended circumstance. For reboot upon activation of the out-of-memory killer, this could for example be achieved by checking that the exit code is 137 (which is guaranteed never to be used by the daemon itself). Furthermore, it is strongly recommended to reduce the `startup-panic-threshold` to match `panic-threshold`, in order to ensure that automatic restarting of the daemon does not unintentionally induce large corrections to the system clock.

## Observability and configuration sockets

The ntpd-rs daemon can expose two sockets:
 - The observe socket is read-only and exposes some of the peer and clock algorithm state.
 - The configuration socket accepts commands and allows changing of some of the configuration settings.

When enabled, these sockets are by default exposed with quite generous permissions (`0o777` for observation and `0o770` for configuration). You should consider restricting access to these sockets, depending on the other software running on the system, and the techniques used for managing it.
