# Network Time Security (NTS)

Network Time Security (NTS) is an extension to the NTP protocol aimed at securing the communication between NTP clients and servers. It guarantees that the servers responses really come from the server. Additionally, it contains countermeasures to ensure that NTP traffic cannot be used to track a specific NTP client across multiple networks. Note that it does not hide the contents of the request or response, so a third party can tell that time is exchanged and the specific time associated with the packets at the server.

## Configuring an NTS time source

To use NTS when communicating with a time source the `"nts"` mode is used. This mode will only work with a NTP server that supports NTS, for example those provided by [netnod](https://www.netnod.se/nts/network-time-security).

```toml
[[peer]]
mode = "nts"
address = "nts.netnod.se"
```

The above assumes that the certificate used by the server is accepted through the root certificates of the system. That should be the case for public NTS servers, but likely won't be for private ones. In those cases the root certificate used in the certificate chain of the server needs to be separately provided to ntpd-rs through the `certificate-authority` option:
```toml
[[peer]]
mode = "nts"
address = "my.private.server"
certificate-authority = "/path/to/server/root/certificate.pem"
```
The root certificate file provided in the above example configuration should be a pem-encoded list of root certificates that should be accepted for the server in addition to those in the system certificate store.

Currently, ntpd-rs does not support using self-signed certificates. If non public certificates are needed, the best option is to create a private certificate authority (CA) locally and use that to sign the server's certificate. Instructions for that are included below in the instructions for configuring ntpd-rs as an NTS server.

## Configuring ntpd-rs as an NTS server


### NTS overview

When using NTS, both the client and server sign and partially encrypt the NTP messages they exchange using symmetric key cryptography. The two parties must first agree on the keys to use for the cryptography via a key exchange. 

The key exchange starts with the client contacting the server over a TCP connection secured with Transport Layer Security (TLS), the same protocol also used for secure web browsing. Over this connection, they then decide on which keys to use. Additionally, the server provides the client with 8 cookies. These cookies are used by the client to tell the server which keys are in use for the session. The client uses each cookie only once to ensure that a third party cannot track it's connection, and each response from the server includes a new cookie to replace the one that was just used.

From the client's perspective a cookie is just an opaque bag of bytes. The server uses the contents of the cookie to identify a client, and can put whatever information in the cookie for this purpose. The cookies that ntdp-rs provides contain the symmetric keys for the connection, encrypted with a key that is only known by the server.

### Configuring key exchange

The key exchange server uses a separate address to listen on, and must be provided with a certificate chain (CA) and private key. An example of how to generate these files is given below.

```toml
[[nts-ke-server]]
key-exchange-listen = "[::]:4460"
certificate-chain-path = "ntpd-rs.test.chain"
private-key-path = "ntpd-rs.test.key"
```

The `key-exchange-listen` must use a different port from the normal NTP server. The default port for key exchange is `4460`. TCP (not UDP like the rest of NTP) will be used for communication with this port. At the moment ntpd-rs does not support running an NTS server on a server without a domain name through which its clients reach it. This can however be a local domain name, such as one configured through `/etc/hosts`. In other words, valid addresses look like `abcd.foo`, and addresses like `123.45.67.89` or `abcd::1234` will not work.

The private key is sensitive information. If extracted, an attacker can compromise all connections to clients. Therefore we suggest restricting read access to this file to the ntp daemon and trusted system administrators.

### Configuring key storage

The previous section configures an key exchange server. However, every time the key exchange server is rebooted all of its clients will need to go through the key exchange process again. By storing the keys to disk this extra work can be prevented.

```toml
[keyset]
key-storage-path="/path/to/store/key/material"
```

The `key-storage-path` should be a path to a file that will be used to store the keys. Like the TLS private key, this file contains sensitive information. If an attacker gains access to this file all client connections can be compromised.

### Generating Certificates

Here we cover generating all of the certificates and keys for setting up a NTS key exchange server. We will focus here on locally signing all the certificates for our server. For setting up a public server with NTS support you will need to request a publicly signed certificate. We suggest to use [letsencrypt](https://letsencrypt.org/) for that use case.

We will use the OpenSSL key and certificate tools to generate what we need. These tools are available through most package managers as the `openssl` package.

**root certificate**: First, we will create a certificate authority (CA) root key and certificate. The CA root key is generated with
```sh
openssl genrsa -des3 -out myCA.key 2048
```
This will ask for a password for the root key. It is recommended that you set one to prevent others from using your CA key should it ever leak.

Next, a root certificate needs to be generated for this key:
```sh
openssl req -x509 -new -nodes -key myCA.key -sha256 -days 1825 -out myCA.pem
```
This will ask for a bunch of information. ntpd-rs does not impose particular requirements to the information in your root certificate, so feel free to leave things empty. The above command gives the certificate a period validity of 5 years. If a different lifetime is desired, change the number following the `-days` argument to the number of days the certificate should be valid. Note that this command bases validity on the current system time, so make sure that it is reasonably accurate.

**server certificate**: Having set up our certificate authority, we can now generate the server key and certificate. First, we generate a private key for the server:
```sh
openssl genrsa -out ntpd-rs.test.key 2048
```
Because this key will be used by the server, we can't protect it with a password, so the above command doesn't enable password protection for it.

Next, just like when requesting a certificate from an external CA, we need to create a certificate signing request.
```sh
openssl req -new -key ntpd-rs.test.key -out ntpd-rs.test.csr
```
Again, ntpd-rs does not impose requirements on the information requested here, so feel free to leave things empty.

Next, we will need to create a file that specifies what our CA thinks the key should be usable for. Create a text file called `ntpd-rs.ext` with the following contents:
```ini
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ntpd-rs.test
```
You can change `ntpd-rs.test` to the domain name of your server.

Finally, we generate the certificate with
```sh
openssl x509 -req -in ntpd-rs.test.csr -CA myCA.pem -CAkey myCA.key -CAcreateserial -out ntpd-rs.test.crt -days 1825 -sha256 -extfile ntpd-rs.ext
```
The above command gives the certificate a period validity of 5 years. If a different lifetime is desired, change the number following the `-days` argument to the number of days the certificate should be valid.

Finally, the ntpd-rs server requires the full certificate chain to be provided to it. In our case it is just the concatenation of `ntpd-rs.test.crt` and `myCA.pem`. We can create that on the command line with
```sh
cat ntpd-rs.test.crt myCA.pem > ntpd-rs.test.chain
```

### Running the example

Now we will run a NTS server and client with the certificates we just generated. Note that running both a client and a server on the same machine is meaningless, and may run into issues around clock updates. Still, it provides a quick way to verify the certificates and configuration.

In our particular case, we need to add `ntpd-rs.test` to `/etc/hosts`. This address is similar to localhost

```
127.0.0.1	localhost
127.0.0.1	ntpd-rs.test
```

Here is the configuration for the client:
```toml
# nts.client.toml

[observability]
log-level = "info"

[[source]]
mode = "nts"
address = "ntpd-rs.test:4460"
certificate-authority = "myCA.pem"

# System parameters used in filtering and steering the clock:
[synchronization]
minimum-agreeing-sources = 1 # because we only have one source
single-step-panic-threshold = 10
startup-step-panic-threshold = { forward = "inf", backward = 86400 }
```

Next, the configuration for the server.


```toml
[observability]
# Other values include trace, debug, warn and error
log-level = "info"

[[source]]
mode = "pool"
address = "ntpd-rs.pool.ntp.org"
count = 4

# Serve NTP on any interface (requires permissions to use udp port 123)
[[server]]
listen = "[::]:123"

[synchronization]
single-step-panic-threshold = 1800
startup-step-panic-threshold = { forward="inf", backward = 1800 }
#accumulated-threshold = 1800

[[nts-ke-server]]
key-exchange-listen = "[::]:4460"
certificate-chain-path = "ntpd-rs.test.chain"
private-key-path = "ntpd-rs.test.key"

# this should not be in `/tmp` in practice because tmp is cleared between reboots 
[keyset]
key-storage-path="/tmp/test-nts/nts-keys.dat"
```

Now in two shells (located in the same directory as the config and certificate files) run 

```
# shell 1
> sudo ntp-daemon -c nts.server.toml

# shell 2
> sudo ntp-daemon -c nts.client.toml
```

The server should show something similar to this

``` 
2023-09-07T12:04:50.116843Z  WARN ntpd::daemon::nts_key_provider: Could not load nts server keys, starting with new set error=Os { code: 2, kind: NotFound, message: "No such file or directory" }
2023-09-07T12:04:50.118319Z  INFO ntpd::daemon::system: new peer source_id=PeerId(1) addr=108.61.164.200:123 spawner=SpawnerId(1)
2023-09-07T12:04:50.118463Z  INFO ntpd::daemon::system: new peer source_id=PeerId(2) addr=87.233.197.123:123 spawner=SpawnerId(1)
2023-09-07T12:04:50.118521Z  INFO ntpd::daemon::system: new peer source_id=PeerId(3) addr=162.159.200.1:123 spawner=SpawnerId(1)
2023-09-07T12:04:50.118620Z  INFO ntpd::daemon::system: new peer source_id=PeerId(4) addr=93.119.5.48:123 spawner=SpawnerId(1)
2023-09-07T12:04:50.123836Z  INFO ntp_proto::algorithm::kalman: No concensus cluster found
2023-09-07T12:04:50.124019Z  INFO ntp_proto::algorithm::kalman: No concensus cluster found
2023-09-07T12:04:50.124230Z  INFO ntp_proto::algorithm::kalman: Offset: 2.6302030967500265+-35.88790881304652ms, frequency: 0+-5773502.691896258ppm
2023-09-07T12:04:50.125135Z  INFO ntp_proto::algorithm::kalman: Offset: 2.5799927862782828+-31.908455915607917ms, frequency: 0+-5000000ppm
```

The nts server keys file is created if it is not found. The NTS client should behave like a normal client

```
2023-09-07T12:05:08.920188Z  INFO ntpd::daemon::system: new peer source_id=PeerId(1) addr=127.0.0.1:123 spawner=SpawnerId(1)
2023-09-07T12:05:08.923677Z  INFO ntp_proto::algorithm::kalman: Offset: -0.1263003796633101+-36.68618458231538ms, frequency: 0+-10000000ppm
2023-09-07T12:05:25.456142Z  INFO ntp_proto::algorithm::kalman: Offset: -0.19231392075128712+-41.33764513245012ms, frequency: 0+-10000000ppm
```

This is proof that the setup for NTS is correct. Again, this is not a realistic setup: server and client should not run on the same machine, and the certificate and key files are not stored properly.
