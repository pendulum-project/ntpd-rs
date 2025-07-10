# NTPv5
The Network Time Protocol is evolving a little bit with NTPv5. This version is
currently in draft and is intended to be the next major revision of the
protocol. While NTPv5 works mostly the same as NTPv4, there are some notable
differences:

- NTPv5 only describes the on-wire protocol, omitting any of the algorithm
  details that were in the previous versions (none of the major NTP
  implementations follow these details precisely, as they are known to be
  suboptimal).
- Support for anything but client and server modes is dropped (ntpd-rs already
  only supports these modes).
- Fields in the NTP server and client messages have been defined more clearly.
- NTPv5 has a better mechanism for handling loop detection.
- Several other minor improvments and changes.

All of this taken together, we believe that NTPv5 is a significant improvement
over NTPv4. Because of this, you can already use ntpd-rs as an NTPv5 client or
server, but this functionality is still experimental and is not enabled by
default.

Version 5 of the NTP protocol is however not backwards compatible with earlier
versions of the protocol, given that some of the fields changed. This is why an
upgrade mechanism is introduced in NTPv5, that allows a client to start with a
NTPv4 packet, and allows the server to upgrade the client to NTPv5. The following
sections describe how to enable this experimental NTPv5 support in ntpd-rs when
used as a client and when used as a server.

!!! Warning

    As NTPv5 is currently still an IETF draft, the draft version of the client
    and server must match, or NTPv5 will not work. This means that if your client
    supports draft 4, the server must also support that same draft 4. To read more
    about the draft NTPv5 specifiction you can check the [IETF website](https://datatracker.ietf.org/doc/draft-ietf-ntp-ntpv5/).

## NTPv5 in clients

Enabling NTPv5 in clients can be done by updating the `[[source]]` config for a
specific source for which you would like to enable NTPv5, using the `ntp-version`
field. By default (`ntp-version = 4`) sources only communicate over NTPv4 (but
accept NTPv3 packets as a response to our v4 packets). Changing this value to
`ntp-version = "auto"` means that the upgrade mechanism will be enabled, and
allowing this source to upgrade to NTPv5 if the server also supports NTPv5.
Changing this value to `ntp-version = 5` means that this source will only ever
send NTPv5 packets, it will no longer support version 4 or below, so only enable
this mode if you are certain a server supports NTPv5. An example configuration is
shown below enabling the auto upgrade mechanism:

```toml
[[source]]
mode = "server"
address = "ntp.example.com"
ntp-version = "auto"
```

## NTPv5 in servers

As servers can accept packets from multiple clients with possibly different
supported NTP versions, you can set a range of versions that is supported in
your server. By default this is only version 3 and 4. To change the default to
also enable NTPv5 support, go to your `[[server]]` configuration and add
`accept-ntp-versions = [3, 4, 5]`. You could also remove `3` in this list to
disable NTPv3 support for example. An example configuration is shown below:

```toml
[[server]]
listen = "0.0.0.0:123"
accept-ntp-versions = [3, 4, 5]
```

If your server also supports Network Time Security (NTS), you will also have to
update your key exchange server configuration. By default the key exchange
server only accepts NTPv4. To change this to support NTPv5, update your
`[[nts-ke-server]]` server configuration and add `accept-ntp-versions = [4, 5]`.
Note that NTPv3 is not supported with NTS, so you are not able to configure it
as an accepted version in your key exchange server. An example config is:

```toml
[[nts-ke-server]]
listen = "[::]:4460"
certificate-chain-path = "/path/to/certificate/chain.pem"
private-key-path = "/path/to/private.key"
accept-ntp-versions = [4, 5]
```
