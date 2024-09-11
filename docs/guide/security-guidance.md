# Hardening ntpd-rs

A correct system clock is critical for both security and the proper functioning of software. For instance, determining the validity of a TLS certificate relies on the system time. Running and debugging a distributed system is much easier, and in some cases only feasible, when the machines are all synchronized. This guide provides some guidance on what to think about when hardening ntpd-rs for your setup.

## The Availability - Correctness tradeoff

When hardening ntpd-rs, one of the larger challenges is a fundamental tradeoff between:

- availability of synchronization: ntpd-rs should actively and continually synchronize with external sources
- risk of missteering: ntpd-rs should not blindly follow external sources: they may be compromised

Many of the measures against missteering increase the risk of unavailability and vice versa. You must decide what the correct balance is for your use case.

For instance, the risk of missteering is large if your system deals with public key cryptography. The security of the current web certificate system hinges on having a rough (<1day) consensus on what time it is. Similarly, the security and functioning of your applications may also be affected. A tradeoff that limits the risk of missteering is probably the correct choice.

On the other hand, a lack of synchronization can cause issues in a distributed system. Such systems require a small upper bound on the time difference between the machines they run on. When time synchronization fails the clocks can quickly drift outside of these bounds and the system may fail. Furthermore it may be most important that the machines are synchronized with each other, not necessarily that they use the true time. Configuring ntpd-rs for maximum availability seems the best approach for this scenario.

Since there is no universally best solution to this tradeoff, you as the end user will have to consider which of these factors weighs more heavily, and adjust your configuration accordingly.

## Limiting incorrect steering

Ntpd-rs can query multiple remote time servers for the current time. This allows it to detect and discard outliers that provide an incorrect time. The synchronization algorithm always requires a strict majority of the reachable servers (those that it is able to actively communicate with) to agree on the current time before making adjustments to the clock. Furthermore, to prevent an attacker to just reduce the available servers to only its own through denial of service attacks, the minimum number of agreeing servers can also be configured through `minimum-agreeing-sources`.

In its operation, ntpd-rs influences the clock in two ways:

* **frequency adjustment:** ntdp-rs can adjust the clock frequency to compensate for hardware inaccuracies and to slowly correct small offsets to the system clock. This process can change the clock by in the worst case at most $1000$ microseconds every second, meaning that any incorrect steering of frequency will need at least 1000 days to reach an offset of 1 day.
* **step adjustment** the second method of steering is stepping the clock. This allows for compensation of larger errors, but also provides more opportunity to an attacker for introducing large errors to the system clock.

Frequency adjustments are essentially impossible to exploit by an attacker. The threat lies in big step adjustments. To prevent incorrect step adjustments, ntpd-rs allows the configuration of step limits. When these limits are exceeded, the daemon assumes that an unrecoverable problem has occurred and aborts. That means no synchronization will occur and the system's time will drift.

The step limits come in three variants:

- `single-step-panic-threshold` sets limits on any individual step during operations. Use of this can limit the maximum change to the clock induced in one operation.
- `startup-step-panic-threshold` is applied instead of the `single-step-panic-threshold` during the first clock correction after startup. Its main use is to allow systems with a poor or no real time clock to still properly synchronize their time on startup, even when a very strict `single-step-panic-threshold` is in place.
- `accumulated-step-panic-threshold` limits the maximum adjustment made through all clock steps combined over the time the daemon is running. It can be used to provide protection against circumvention of the step panic threshold through repeated steps just below the `single-step-panic-threshold`.

What values to choose for these thresholds depends on what the expected maximum offset of the system clock will be during normal operations and startup.

Again, note that the thresholds are enforced through ntpd-rs aborting when they are exceeded. Hence, strict values for these will limit the daemons ability to automatically adjust to sudden changes to the clock, potentially decreasing availability of the time synchronization.

### The risks of rebooting ntpd-rs

Because the `startup-step-panic-threshold` is typically higher than the `single-step-panic-threshold`, rebooting ntpd-rs makes bigger step adjustments possible. Furthermore, rebooting clears the total accumulated step, and repeated reboots can allow an attacker to bypass the protections offered by `accumulated-step-panic-threshold`.

For these reasons we recommend to not automatically restart ntpd-rs. Rather, an administrator should check on a stopped ntpd-rs process to determine whether a restart is benign at the current point in time or if it could worsen an ongoing attack. In the latter case, the attack must first be mitigated before allowing the ntpd-rs daemon to restart.

## Increasing availability

The best way to increase availability of time synchronization is to increase the number of servers ntpd-rs queries for the current time. When combined with a (relatively) small value for `minimum-agreeing-sources`, this will allow ntpd-rs to keep synchronizing the local time even if multiple upstream servers fail.

For servers being completely unavailable, this is the difference between the number of configured time sources and `minimum-agreeing-sources`. However, note that at most half the servers can fail with incorrect time information before impacting time synchronization.

The downside of a large number of upstream time servers is that an attacker aimed at missteering your local clock is provided with more avenues to do so, because they will need to compromise a smaller fraction of upstream servers to gain clock control. The attacker can then ensure synchronization with that subset through denial of service attacks on the other upstream servers.

## Configuration, logs and observability

There are more aspects of ntpd-rs besides clock steering that must be considered for secure operations.

The clock steering is based on the ntpd-rs configuration file. If an attacker can modify this configuration file, all protections configured in it are meaningless. We recommend that operating system facilities (e.g. permissions) be used to restrict who can edit the configuration and, depending on what threats are expected, who can read it.

Similarly, for logs it is recommended to restrict who can read the logs. It is also strongly advisable to configure log rotation and limits on the maximum size of the log through the systems logging facilities, to prevent logs from accidentally becoming so large as to impede normal system operation. When configured with a `log-level` of info or higher, the daemon should not log in direct response to random network traffic. However, log output is proportional to the number of remote time sources configured.

Furthermore, the ntpd-rs daemon can be configured to expose two sockets:
- The observe socket is read-only and exposes some of the source and clock
  algorithm state.
- The configuration socket accepts commands and allows changing of some of the
  configuration settings.

When enabled, these sockets are by default exposed with quite generous
permissions (`0o666` for observation and `0o660` for configuration). For a hardened setup, it may be desirable to further restrict access to these sockets, or to leave them disabled. The configuration allows stricter permissions for these sockets to be configured through the `observation-permissions` and `configure-permissions` options.
