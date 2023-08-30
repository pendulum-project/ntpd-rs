# Hardening ntpd-rs

Both for security as well as the proper functioning of software, having the correct time in the system clock is critical. Correct time is fundamental for judging the validity of TLS certificates. When running distributed software, it can also be critical for the correct functioning of that software. This guide intends to provide some guidance on what to think about when hardening ntpd-rs for your setup.

## The Availability - Correctness tradeoff

When hardening ntpd-rs, one of the larger challenges is the tradeoff between availability of synchronization, and the risk of missteering at the command of an attacker. Many of the measures against missteering increase the risk of unavailability and vice versa.

Missteering at the command of an attacker creates risks when using public key cryptography. The security of the current web certificate system hinges on having a rough (<1day) consensus on what time it is. Similarly, security and or functioning of your applications may also be affected.

On the other hand, some distributed systems require a small upper bound on the time difference between the machines they run on. Such systems may quickly drift out of those bounds should time synchronization fail, potentially causing the distributed system to fail or to show incorrect behaviour.

Since there is no universally best solution to these issues, you as the end user will have to consider which of these factors weighs more heavily, and adjust your configuration accordingly.

## Limiting incorrect steering

Ntpd-rs can query multiple remote time servers for the current time. This allows it to detect when a small subset of these servers is incorrect and automatically discard those. It always requires a strict majority of the reachable servers (those that it is able to actively communicate with) to agree on the current time before making adjustments to the clock. Furthermore, to prevent an attacker to just reduce the available servers to only its own through denial of service attacks, the minimum number of agreeing servers can also be configured through `minimum-agreeing-peers`.

In its operation, ntpd-rs influences the clock in two ways. First, it can adjust the clock frequency to compensate for hardware inaccuracies and to slowly correct small offsets to the system clock. This process can change the clock by in the worst case at most $1000$ microseconds every second, meaning that any incorrect steering of frequency will need at least 1000 days to reach an offset of 1 day.

The second method of steering is stepping the clock. This allows for compensation of larger errors, but also provides more opportunity to an attacker for introducing large errors to the system clock. To prevent this, ntpd-rs allows the configuration of step limits. Once these are exceeded, the daemon assumes something is very wrong, and rather than trying to correct it itself it then shuts down to prevent making the problem worse.

The step limits come in three variants. The first is `single-step-panic-threshold`, which provides limits on any individual step during operations. Use of this can limit the maximum change to the clock induced in one operation.

The second is the `startup-step-panic-threshold`. This is applied instead of the `single-step-panic-threshold` during the first clock correction after startup. Its main use is to allow systems with a poor or no real time clock to still properly synchronize their time on startup, even when a very strict `single-step-panic-threshold` is in place.

Finally, there is the `accumulated-step-panic-threshold`, which limits the maximum adjustment made through all clock steps combined over the time the daemon is running. It can be used to provide protection against circumvention of the step panic threshold through repeated steps just below the `single-step-panic-threshold`.

Choosing values for these thresholds depend on what the expected maximum offset of the system clock will be during normal operations and startup. Note that all these limits are enforced through ntpd-rs inactivating itself once they are exceeded. Hence, strict values for these will limit the daemons ability to automatically adjust to sudden changes to the clock, potentially decreasing availability of the time synchronization.

### The risks of rebooting ntpd-rs

Rebooting ntpd-rs can have a significant negative impact on its protections against missteering. First of all, after a reboot the first step is once again done under the startup regime. If this regime is more permissive than the normal step protection, repeated reboots can allow the clock to quickly be steered to a different time.

Second, a reboot of ntpd-rs clears the totals for jumps made so far. Thus, repeated reboots can allow an attacker to bypass the protections offered by `accumulated-step-panic-threshold`.

For these reasons we recommend to not automatically restart ntpd-rs. Rather, an administrator should check on a stopped ntpd-rs process to determine whether a restart is benign at the current point in time or if it could help an ongoing attack. In the latter case, the attack must first be mitigated before allowing the ntpd-rs daemon to restart.

## Increasing availability

The best way to increase availability of time synchronization is to increase the number of servers ntpd-rs queries for the current time. When combined with a (relatively) small value for `minimum-agreeing-peers`, this will allow ntpd-rs to keep synchronizing the local time even if multiple upstream servers fail.

For servers being completely unavailable, this is the difference between the number of configured time sources and `minimum-agreeing-peers`. However, note that at most half the servers can fail with incorrect time information before impacting time synchronization.

The downside of a large amount of upstream time servers is that it can offer an attacker aimed at missteering your local clock more avenues to do so, as it will need to compromise a smaller fraction of them to gain clock control. It can then ensure synchronization with that subset through denial of service attacks on the other upstream servers.

## Configuration, logs and observability

Apart from hardening the way the clock is controlled for your specific application, there is also the hardening of the configuration channels and diagnostic information to be considered. It is recommended that operating system facilities be used to restrict who can edit the configuration and, depending on what threats are expected, who can read it.

Similarly, for logs it is recommended to restrict who can read the logs. It is also strongly advisable to configure log rotation and limits on the maximum size of the log through the systems logging facilities, to prevent logs from accidentally becoming so large as to impede normal system operation. When configured with a `log-level` of info or higher, the daemon should not log in direct response to random network traffic. However, log output is proportional to the amount of remote time sources configured.

Furthermore, the ntpd-rs daemon can be configured to expose two sockets:
- The observe socket is read-only and exposes some of the peer and clock
  algorithm state.
- The configuration socket accepts commands and allows changing of some of the
  configuration settings.

When enabled, these sockets are by default exposed with quite generous
permissions (`0o666` for observation and `0o660` for configuration). For a hardened setup, it may be desirable to further restrict access to these sockets, or to leave them disabled. The configuration allows stricter permissions for these sockets to be configured through the `observation-permissions` and `configure-permissions` options.
