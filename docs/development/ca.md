# Private CA and certificate

!!! Danger

    Setting up your own CA is not recommended except for development purposes
    and setting up internal-only networks. For all other purposes, we would
    recommend to use a widely trusted CA for issuing certificates. See the
    [NTS guide](../guide/nts.md) for more information.

Setting up NTS-KE when your server has no public domain name is still possible
by creating your own certificate authority (CA). To setup a CA and the
certificate for our server we will use the OpenSSL command line tools. They are
available through most package managers as the `openssl` package.

## Root certificate
We will start by generating a CA root key and certificate. To start, create a
directory where we will store all our certificate data:

```sh
mkdir "/path/to/some/ca-data"
cd "/path/to/some/ca-data"
```

To generate the root key, use this OpenSSL command:

```sh
openssl genrsa -des3 -out ca.key 2048
```

This will ask for a password for the root key. It is recommended that you set
one, as this will prevent others from directly using your CA key should it ever
leak. However, for development purposes you may opt to omit a password by
removing the `-des3` CLI flag. Once the key is generated, we can generate a CA
root certificate by using this command:

```sh
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1825 -out ca.pem
```

Here, `-days` is the number of days that this certificate is valid, the value in
the command here results in a validity of five years. OpenSSL will ask for
several pieces of information during the setup of the root certificate. The
ntpd-rs daemon does not impose particular requirements to the information in
your root certificate, so feel free to leave things empty. Note that this
command bases the certificate validity based on the current system time, so make
sure that it is reasonably accurate.

## Server certificate
Once our CA root is setup, we can continue generating the server key and
certificate. First, we start by generating a private key for the server:

```sh
openssl genrsa -out ntpd-rs.test.key 2048
```

This time we omit the `-des3` CLI flag, so the private key is not protected with
a password. The ntpd-rs daemon does not support password encrypted private keys,
so we cannot password protect our private key. Once the private key is
generated, we need to create a certificate signing request. We again can use
openssl to do this for us:

```sh
openssl req -new -key ntpd-rs.test.key -out ntpd-rs.test.csr
```

OpenSSL will once again ask for some information, but ntpd-rs once again does
not impose any requirements on the information requested, so feel free to leave
things empty once again. With the certificate signing request generated, we now
only need a little bit of configuration to tell the CA root how the generated
certificate will be used, to do this, create a file called `ntpd-rs.ext` with
the following contents, replacing the `ntpd-rs.test` domain name with your own
domain name.

```ini title="/path/to/some/ca-data/ntpd-rs.ext"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ntpd-rs.test
```

Note that the domain name does not actually have to exist, but it will be the
domain name that clients somehow have to connect to (e.g. by setting an
`/etc/hosts` entry). We now have enough information to generate a certificate:

```sh
openssl x509 -req -in ntpd-rs.test.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out ntpd-rs.test.crt -days 1825 -sha256 -extfile ntpd-rs.ext
```

The above command gives the certificate a period validity of 5 years. If a
different lifetime is desired, change the number following the `-days` argument
to the number of days the certificate should be valid. The generated certificate
should be concatenated together with the CA certificate, as ntpd-rs needs the
full certificate chain in order to operate. We can use a simple command to do
this:

```sh
cat ntpd-rs.test.crt ca.pem > ntpd-rs.test.chain.pem
```

## Using the generated certificate
We are now ready to configure the key exchange part of NTS with our generated
certificate. Simply update your `/etc/ntpd-rs/ntp.toml` configuration with the
following `[[nts-ke-server]]` section (or update an existing section):

```toml title="/etc/ntpd-rs/ntp.toml"
# ...

[[nts-ke-server]]
listen = "[::]:4460"
certificate-chain-path = "/path/to/some/ca-data/ntpd-rs.test.chain.pem"
private-key-path = "/path/to/some/ca-data/ntpd-rs.test.key"

# ...
```

Finally, restart your ntpd-rs daemon by running `systemctl restart ntpd-rs`.
Your server should now be ready to handle NTS!

!!! Danger

    When configured as above, it is important to ensure that the TLS private key
    can only be read by ntpdaemon and trusted system administrators. An attacker
    can use this key material to compromise all connections to clients.

## Client setup
Once your server was setup, you will need to distribute the certificate
authority root certificate to clients that will be using the NTS server. Note
that you should only ever share the `ca.pem` file and never the `ca.key` file!

In your client, now you will need to make sure that the domain name under which
you reach the server is the same as the domain name for which you configured
the server certificate. In our example above we used the domain name
`ntpd-rs.test`. If we wanted the server to be able to reach itself, we can
simply add a `/etc/hosts` entry for this, like such:

```txt title="/etc/hosts" hl_lines="3"
...
127.0.0.1   localhost
127.0.0.1   ntpd-rs.test
...
```

Now in your client configuration, you can setup a NTS source with our private
CA root certificate:

```toml title="/etc/ntpd-rs/ntp.toml"
# ...

[[source]]
mode = "nts"
address = "ntpd-rs.test"
certificate-authority = "/path/to/some/ca-data/ca.pem"

# ...
```

Of course, if you are setting up another client, do not forget to copy the
`ca.pem` file to that client!
