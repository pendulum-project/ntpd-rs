# NTS pool experiments

Network Time Security (NTS) is an extension to the NTP protocol aimed at
securing the communication between NTP clients and servers. An experimental
pool for servers supporting NTS has recently been set up at
<https://experimental.ntspooltest.org/>

## Using the SRV variant of the pool

NTPD-rs versions 1.8.0 and later support using the SRV variant of the
experimental pool. They can use the pool by adding the following source to
their configuration:
```toml
[[source]]
mode = "nts-pool"
enable-srv-resolution = true
address = "srv.experimental.ntspooltest.org"
```

Note that SRV pool support is still experimental and usage of it may trigger bugs.

## Participating in the NTS pool

NTPD-rs versions newer than 1.7.0-alpha.20251003 support being added to this
pool. This guide will assume you are running a version more recent than this,
and have already setup an NTS server using the instructions in [our NTS guide](./nts.md).

### Adding your server

To add an NTS server to the pool, on the pool website add the domain name of
the server on the `Time sources` page after logging in. The pool will give you
an authentication key the pool will use to authenticate itself to your NTS
server. This key will need to be added to the ntpd-rs configuration to allow
the pool to handle NTS key exchange connections for your server.

To add this key, modify the ntpd-rs configuration at `/etc/ntpd-rs/ntp.toml`,
adding to the `[[nts-ke-server]]` section the following:
```toml
accepted-pool-authentication-tokens = ["<YOUR TOKEN HERE>"]
```

After restarting your server, it will start accepting requests from the pool,
and you will start to see your score on the pool website increase. When this
happens, your server is succesfully configured for use in the pool.
