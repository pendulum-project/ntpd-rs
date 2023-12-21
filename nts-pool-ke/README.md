# NTS pool KE

The NTS pool KE experimental feature provides an analogue to the [ntp pool](https://www.ntppool.org/en/) that supports Network Time Security (NTS).

The technical details are described in the [draft RFC](TODO).

## Building

The NTS pool KE feature is behind a feature flag that is disabled by default. Enabling this feature requires a from-source build. 

```sh
> cargo build --release --features "unstable_nts-pool"

> ls target/release/
ntp-daemon
nts-pool-ke
...
```

The command builds a version of `ntp-daemon` that accepts configuration for being an NTS pool client and can be an NTS pool KE server. The `nts-pool-ke` binary is the actual pool.

## Setup

An (insecure!) example setup is given by the `unsafe.*.toml` files in this directory. The important bits are written out here.

### Client

Because this is a build with the NTS pool KE enabled, the client accepts a source of type `"nts-pool"`, for instance:

```toml
# client.toml

[[source]]
mode = "nts-pool"
address =  "custom.nts.pool:4460"
certificate-authority = "ca.pem"
count = 2
```

Configuration for the client is otherwise unchanged.

### Pool

The pool is configured with a custom `pool.toml` configuration file. Because the pool behaves like both a server and a client, it needs certificate information that combines the configuration that we normally see for NTS clients and servers.

```toml
# pool.toml

[nts-pool-ke-server]
listen = "0.0.0.0:4460"
certificate-authority-path = "ca.pem"
certificate-chain-path = "end.fullchain.pem"
private-key-path = "end.key"
key-exchange-servers = [
    { domain = "nts.server.1", port = 8081 },
    { domain = "nts.server.2", port = 8080 },
]
```

### Server

Server configuration is mostly standard, but the certificate for an NTS pool must be specifically allow-listed.

```toml
# server.toml

[[nts-ke-server]]
listen = "0.0.0.0:8080"
certificate-chain-path = "end.fullchain.pem"
private-key-path = "end.key"
authorized-pool-server-certificates = ["end.pem"]
key-exchange-timeout-ms = 1000
```

### Certificate

The NTS pool KE requires a relatively complex certificate setup. Here we provide some scripts for generating TLS certificates and keys.
