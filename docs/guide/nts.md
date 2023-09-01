# Network Time Security

Network Time Security (NTS) is an extension to the NTP protocol aimed at securing the communication between NTP clients and servers. It guarantees that the severs responses really come from the server. Additionally, it contains countermeasures to ensure that NTP traffic cannot be used to track a specific NTP client across multiple networks. Note that it does not hide the contents of the request or response, so a third party can tell that time is exchanged and the specific time associated with the packets at the server.

## Configuring an NTS server as time source

Configuring a public NTS server, for example those provided by [netnod](https://www.netnod.se/nts/network-time-security), is fairly straightforward:
```toml
[[peer]]
mode = "nts"
address = "nts.netnod.se"
```

The above assumes that the certificate used by the server is accepted through the root certificates of the system. If this is not the case, the root certificate used in the certificate chain of the server needs to be separately provided to ntpd-rs. This can be done through the `certificate-authority` option:
```toml
[[peer]]
mode = "nts"
address = "my.private.server"
certificate-authority = "/path/to/server/root/certificate.pem"
```
The root certificate file provided in the above example configuration should be a pem encoded list of root certificates that should be accepted for the server in addition to those in the system certificate store.

Currently, ntpd-rs does not support using self-signed certificates. If non public certificates are needed, the best option is to create a private CA locally and use that to sign the server's certificate. Instructions for that are included below in the instructions for configuring ntpd-rs as an NTS server.

## Configuring ntpd-rs as an NTS server

To configure ntpd-rs as a server, we need to configure three things. First, ntpd-rs needs to be configured to work as a normal NTP server. Second, we need to enable the server components that allow key exchange with clients. Finally, we need to configure storage for internal keys to ensure clients don't need to reconnect on a reboot of the server.

The process of setting up an NTS server is significantly harder than configuring an NTS time source. We assume here some experience with [setting up a non-NTS NTP server](TODO), and will assume you already have that running on the target machine.

Furthermore, NTPD-rs currently does not support running an NTS server on a server without a domain name through which its clients reach it. This can however be a local domain name, such as one configured through `/etc/hosts`.

### Certificates

Before setting up the key exchange part of the server, we will first need to create the required key material. We will focus here on locally signing all the certificates for our server. For setting up a public server with NTS support you will need to request a publicly signed certificate. We suggest to use [letsencrypt](https://letsencrypt.org/) for that use case.

For making our certificates, we will use the OpenSSL key and certificate tools. These are available through most package managers as the `openssl` package.

**root certificate**: First, we will create a CA root key and certificate. The CA root key is generated with
```sh
openssl genrsa -des3 -out myCA.key 2048
```
This will ask for a password for the root key. It is recommended that you set one as this will prevent others from using your CA key should it ever leak.

Next, a root certificate needs to be generated for this key:
```sh
openssl req -x509 -new -nodes -key myCA.key -sha256 -days 1825 -out myCA.pem
```
This will ask for a bunch of information. NTPD-rs does not impose particular requirements to the information in your root certificate, so feel free to leave things empty. The above command gives the certificate a period validity of 5 years. If a different lifetime is desired, change the number following the `-days` argument to the number of days the certificate should be valid. Note that this command bases validity on the current system time, so ensure it is reasonably accurate.

**server certificate**: Having set up our CA, we can now generate the server key and certificate. First, we generate a private key for the server:
```sh
openssl genrsa -out ntpd-rs.test.key 2048
```
As this key will be used by the server, we can't protect it with a password, so the above command doesn't enable password protection for it.

Next, just like when requesting a certificate from an external CA, we need to create a certificate signing request.
```sh
openssl req -new -key ntpd-rs.test.key -out ntpd-rs.test.csr
```
Again, NTPD-rs does not impose requirements on the information requested here, so feel free to leave things empty.

Next, we will need to create a file that specifies what our CA thinks the key should be usable for. Create a text file called `ntpd-rs.ext` with the following contents:
```ini
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ntpd-rs.test
```
You can change ntpd-rs.test to the domain name of your server.

Finally, we generate the certificate with
```sh
openssl x509 -req -in ntpd-rs.test.csr -CA myCA.pem -CAkey myCA.key -CAcreateserial -out ntpd-rs.test.crt -days 1825 -sha256 -extfile ntpd-rs.ext
```
The above command gives the certificate a period validity of 5 years. If a different lifetime is desired, change the number following the `-days` argument to the number of days the certificate should be valid.

Finally, the ntpd-rs server requires the full certificate chain to be provided to it, so let's generate it with
```sh
cat ntpd-rs.test.crt myCA.pem > ntpd-rs.test.chain
```

### Configuring key exchange

We are now ready to configure the key exchange part of NTS. This is used by clients when setting up a connection.
```toml
[[nts-ke-server]]
key-exchange-listen = "[::]:4460"
certificate-chain-path = "ntpd-rs.test.chain"
private-key-path = "ntpd-rs.test.key"
```
Note that this needs to listen on its own port. Furthermore, the key exchange happens over a TCP connection rather than over UDP packets.

When configured as above, it is important to ensure that the TLS private key can only be read by NTP-daemon and trusted system administrators. An attacker can use this key material to compromise all connections to clients.


### Configuring key storage

After the above steps, we now have a working configuration for an NTS server. However, every time we reboot our server, all of its clients will need to go through the key exchange process again. To ensure clients don't experience negative consequences on server reboots, we need to configure the server to save key materials it generates to disk.
```toml
[keyset]
key-storage-path="/path/to/store/key/material"
```
Here, the `key-storage-path` should be set to a path

Note that, like with the TLS private key, an attacker having access to the file specified under `key-storage-path` can compromise all connections to clients.
