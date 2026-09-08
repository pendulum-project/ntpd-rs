Security policy
===============

**Do not report security vulnerabilities through public GitHub issues.**
Instead, you can report security vulnerabilities using [our security page],
or send them by email to security+ntpdrs@tweedegolf.com.

Please include as much of the following information as possible:

 * Type of issue (e.g. buffer overflow, privilege escalation, etc.)
 * The location of the affected source code (tag/branch/commit or direct URL)
 * Any special configuration required to reproduce the issue
 * If applicable, which platforms are affected
 * Step-by-step instructions to reproduce the issue
 * Impact of the issue, including how an attacker might exploit the issue

Please note that it may take us several days to respond to your report.

## What classifies as security vulnerabilities

We are primarily concerned with, and release advisories for, security issues in
released versions of ntpd-rs, affecting non-experimental features. Furthermore,
we consider the configuration, and any configured NTS servers as within the
security boundary.

In particular, this means we handle the following through regular issues:
- Any bug that is only present on the development branch.
- Any bug in experimental features.
- Any problems caused by very unusual configurations, or situations where the
  configuration can be considered the main security issue.

## Preferred Languages

We prefer to receive reports in English. If necessary, we also understand Dutch.

## Disclosure Policy

We adhere to the principle of [coordinated vulnerability disclosure].

Security Advisories
===================
Security advisories will be published on our [github advisories page] and
possibly through other channels.

[our security page]: https://github.com/pendulum-project/ntpd-rs/security
[coordinated vulnerability disclosure]: https://vuls.cert.org/confluence/display/CVD/Executive+Summary
[github advisories page]: https://github.com/pendulum-project/ntpd-rs/security/advisories
