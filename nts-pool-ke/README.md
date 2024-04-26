# NTS pool KE

The NTS pool KE experimental feature provides an analogue to the [ntp pool](https://www.ntppool.org/en/) that supports Network Time Security (NTS).

The technical details are described in the [draft RFC](https://github.com/pendulum-project/nts-pool-draft).

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

## Example

An (insecure!) example setup is given by the `unsafe.*.toml` files in this directory. Purely for testing, this example can be run on a single machine as follows. In three different terminals, run

```
sudo target/release/ntp-daemon -c nts-pool-ke/unsafe.nts.server.toml
target/release/nts-pool-ke -c nts-pool-ke/unsafe.pool.toml
sudo target/release/ntp-daemon -c nts-pool-ke/unsafe.nts.client.toml
```

The server should show something like this

```
> sudo target/release/ntp-daemon -c nts-pool-ke/unsafe.nts.server.toml

2023-12-21T10:49:12.702642Z  INFO ntpd::daemon::system: new source source_id=SourceId(1) addr=213.109.127.82:123 spawner=SpawnerId(1)
2023-12-21T10:49:12.702693Z  INFO ntpd::daemon::system: new source source_id=SourceId(2) addr=94.198.159.16:123 spawner=SpawnerId(1)
2023-12-21T10:49:12.702706Z  INFO ntpd::daemon::system: new source source_id=SourceId(3) addr=154.51.12.215:123 spawner=SpawnerId(1)
2023-12-21T10:49:12.702719Z  INFO ntpd::daemon::system: new source source_id=SourceId(4) addr=45.138.55.60:123 spawner=SpawnerId(1)
2023-12-21T10:49:12.709153Z  INFO ntp_proto::algorithm::kalman: Offset: 2.2252593194659007+-70.88905127356101ms, frequency: 0+-10000000ppm
2023-12-21T10:49:12.709438Z  INFO ntp_proto::algorithm::kalman: Offset: 1.6675194083763052+-50.70180376962068ms, frequency: 0+-7071067.811865476ppm
2023-12-21T10:49:12.711005Z  INFO ntp_proto::algorithm::kalman: Offset: 1.3434683112795662+-43.24338657667398ms, frequency: 0+-5773502.691896257ppm
```

The NTS pool KE should show

```
> target/release/nts-pool-ke -c nts-pool-ke/unsafe.pool.toml

2023-12-21T10:49:34.628308Z  INFO nts_pool_ke: listening on 'Ok(0.0.0.0:4460)'
2023-12-21T10:49:37.765321Z  INFO nts_pool_ke: received records from the client
2023-12-21T10:49:37.766481Z  INFO nts_pool_ke: checking supported algorithms for 'localhost:8081'
2023-12-21T10:49:37.767102Z  INFO nts_pool_ke: checking supported algorithms for 'localhost:8080'
2023-12-21T10:49:37.769478Z  INFO nts_pool_ke: established connection to the server
2023-12-21T10:49:37.769717Z  INFO nts_pool_ke: received supported algorithms from the NTS KE server
2023-12-21T10:49:37.770599Z  INFO nts_pool_ke: fetching cookies from the NTS KE server
2023-12-21T10:49:37.770834Z  INFO nts_pool_ke: received cookies from the NTS KE server
2023-12-21T10:49:37.770868Z  INFO nts_pool_ke: wrote records for client
```

Finally the client should show

```
> sudo target/release/ntp-daemon -c nts-pool-ke/unsafe.nts.client.toml

2023-12-21T13:11:03.577635Z  INFO ntpd::daemon::system: new source source_id=SourceId(1) addr=127.0.0.1:123 spawner=SpawnerId(1)
2023-12-21T13:11:03.580097Z  INFO ntp_proto::algorithm::kalman: Offset: -0.043484615172139515+-44.92576728378405ms, frequency: 0+-10000000ppm
```

> NOTE: the client may need a while to synchronize in this scenario. So long as no warnings are printed things should eventually settle and start to synchronize.

## Setup

An (insecure!) example setup is given by the `unsafe.*.toml` files in this directory. The important bits are highlighted here.

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

Server configuration is mostly standard, but the certificate for an NTS pool must be specifically allow-listed by specifying them using `authorized-pool-server-certificates`. The files listed there must consist of just a single certificate, *not* a certificate chain.

```toml
# server.toml

[[nts-ke-server]]
listen = "0.0.0.0:8080"
certificate-chain-path = "end.fullchain.pem"
private-key-path = "end.key"
authorized-pool-server-certificates = ["end.pem"]
key-exchange-timeout-ms = 1000
```

### Generating Certificates

The NTS pool KE requires a relatively complex certificate setup. Documentation for generating a certificate authority can be found [in our docs](https://docs.ntpd-rs.pendulum-project.org/development/ca/).  The `test-keys/gen-cert.sh` script generates a certificate and private key for a server.
