# Network Time Security

Network Time Security (NTS) is an extension to the NTP protocol aimed at
securing the communication between NTP clients and servers. It's most important
goals are:

* Verification of the server identity to make sure you receive time from the
  source you expected to receive time information from.
* Making sure that time packets are authentic, i.e. they were not modified in
  transit.
* Preventing the replay of previously sent time packets and verification that
  time packets were sent in response to a request by a client.

Although NTS has the capability to encrypt parts of the message, the time
information itself is considered public information and as such is not
encrypted. Third parties can thus see what the exchanged time information was,
but they cannot modify it.

## Using an NTS source
You can use existing public NTS servers with ntpd-rs by simply adding a source
with mode `nts`. For example, [netnod] has public NTS servers, to use them you
simply configure a source like this:

[netnod]: https://www.netnod.se/nts/network-time-security

```toml
[[source]]
mode = "nts"
address = "nts.netnod.se"
```

The certificate of the NTS server is verified by using the installed system
certificates on your machine. However, some NTS servers use a custom or private
certificate authority (CA) that is unknown by your system to sign their
certificates, in such cases you will also need to specify the additional
certificate authority by setting a `certificate-authority` option:

```toml
[[source]]
mode = "nts"
address = "my.private.server.example.com"
certificate-authority = "/path/to/certificate/authority.pem"
```

!!! Warning

    The ntpd-rs daemon does not support self-signed certificates. Servers that
    only have a self-signed certificate cannot be used. Either setup a private
    certificate authority and use that CA to sign the certificate for the
    server, or choose an alternative NTS server.

## NTS protocol
When using NTS, both the client and server sign and partially encrypt the NTP
messages they exchange using symmetric key cryptography. For this, the client
and server first need to exchange the keys they will use. NTS solves this
problem with a separate key exchange.

For the key exchange, the client first contacts the server over a TCP connection
secured with TLS, the same protocol also used for secure web browsing. Over this
connection, they then decide on which keys to use. Finally, the server provides
the client with eight cookies. These cookies are used by the client to tell the
server which keys are in use for the session. The client uses each cookie only
once to ensure that a third party cannot track its connection, and it receives a
new cookie with each server response.

These cookies are an opaque bag of bytes for the client, and the server can put
in them whatever it finds useful for identifying the proper keys for that
particular client. Cookies do however have to be unique, a cookie cannot be
reused once a message with it was sent. If the client ever runs out of cookies
(a cookie is lost whenever an NTP message or the response to that message got
lost) or if the server somehow no longer understands the cookies it receives
from clients, the server and client will have to redo the key exchange.

## Setting up an NTS server
Setting up an NTS server involves several steps. Before you get started, make
sure you already have a [working NTP server](./server-setup.md).

For the key exchange part of NTS, we need to setup a specific key exchange
server in the daemon. NTS-KE servers by default run on TCP port 4460. Note the
difference here, where the NTP server uses UDP versus the key exchange protocol
running on TCP. To do this, we add a `[[nts-ke-server]]` section to our
configuration:

```toml
[[nts-ke-server]]
listen = "[::]:4460"
certificate-chain-path = "/path/to/certificate/chain.pem"
private-key-path = "/path/to/private.key"
```

!!! Note

    The ntpd-rs daemon currently does not support running an NTS server without
    an associated domain name through which its clients reach it. If you are
    setting up your own private CA, you can however setup a local domain name
    (e.g. `example-nts.local`), such as one configured through `/etc/hosts`.
    Raw IPv4 or IPv6 addresses such as `192.168.1.1` are unsupported.

Once the NTS-KE server is setup the NTP server you have setup in your
configuration will automatically start responding to valid NTS messages, there
is no additional setup required.

Getting a certificate for your server can be a quite involved process. We would
recommend you use a [Let's Encrypt][1] ACME client for setting up a TLS
certificate (similarly to how you would set this up for a webserver). Below you
will find some examples using some popular clients.

[1]: https://letsencrypt.org/

!!! Note

    For development purposes (or in very specific networking scenarios) it might
    be useful to setup your own CA that allows you to setup a private
    certificate for your NTS server. This is not recommended for general usage,
    but we have a guide for [setting up your own CA](../development/ca.md).

### Configuring key storage
After having enabled an NTS-KE server you will have a working configuration for
an NTS server. However, every time we reboot our server, all of its clients will
need to go through the key exchange process again. To ensure that clients don't
experience any negative consequences on server reboots, we can configure the
server to store key materials it generates to disk. We can do this by adding an
addition `[keyset]` section, and setting the `key-storage-path` within it:

```toml
[keyset]
key-storage-path="/path/to/store/key/material"
```

Note that, like with the TLS private key, an attacker having access to the file
specified under `key-storage-path` can compromise all connections to clients.
Furthermore, the daemon will not create any parent directories if they don't exist.
It will create the file if it doesn't exist.

### Certificates using certbot
Let's encrypt recommends using certbot for managing certificates on your server.
To get started, you should follow the [certbot installation instructions][2].
You can follow the instructions for *'Other'* software for your specific OS.
Once you've installed certbot, verify that it is working as intended:

[2]: https://certbot.eff.org/instructions

```sh
certbot --version
```

Once you've installed certbot, you can run a simple command to get a certificate
for your domain, replacing the email address and domain name with your own:

```sh
certbot certonly --standalone -n --email "[you@example.com]" --agree-tos -d "[time.example.com]" --deploy-hook "systemctl restart ntpd-rs"
```

The command above assumes that traffic from TCP port 80 can be received from the
internet by your server and that there is no other software (such as another
webserver) running on that port. When you have an existing webserver already
listening on port 80 you can use that as well. Or if http traffic is not
possible you can also use DNS based verification, but those go beyond this
guide. Please read the [certbot documentation][3] for more details.

Certbot automatically sets up a task that renews these certificates, because
Let's Encrypt certificates are valid for only 90 days. The `--deploy-hook`
argument tells certbot to restart the ntpd-rs daemon whenever a new certificate
is issued, because ntpd-rs does not automatically reload the certificate files.

We can now update our configuration with the paths of the generated certificate
files (replacing the domain name with the domain name for which you requested a
certificate):

```toml
[[nts-ke-server]]
listen = "[::]:4460"
certificate-chain-path = "/etc/letsencrypt/live/[time.example.com]/fullchain.pem"
private-key-path = "/etc/letsencrypt/live/[time.example.com]/privkey.pem"
```

Finally, restart the ntpd-rs daemon using `systemctl restart ntpd-rs`. Your
server should now be able to handle NTS traffic!

[3]: https://eff-certbot.readthedocs.io/en/stable/using.html

### Certificates using lego
Lego is an alternative Let's Encrypt client implementation. On many OSses it can
be installed from the package repository by searching for a `lego` package. If
it is not available from your OS vendor, you can also find a download from the
[lego github page][4].

To generate a new certificate, you can issue the following command, replacing
the email address and domain name with your own:

```sh
lego --email "[you@example.com]" --http --domains "[time.example.com]" --accept-tos --path /var/lib/lego run
```

Lego does not automatically renew certificates when they expire, but we can
setup a crontab entry to automate the renewal process. The lego renew command
only renews when a certificate is due to expire. To do this, place an executable
shell script in `/etc/cron.daily` (replacing the email address and domain name
with your own as before):

```sh
cat <<'EOF' > /etc/cron.daily/renew-certificate
#!/usr/bin/env bash
lego --email "[you@example.com]" --http --domains "[time.example.com]" --accept-tos --path /var/lib/lego renew --renew-hook "systemctl restart ntpd-rs
EOF
chmod +x /etc/cron.daily/renew-certificate
```

Because the ntpd-rs daemon does not automatically restart whenever the
certificates are updated, we instruct lego to restart our daemon using the
`--renew-hook` argument.

The commands above assume that traffic from TCP port 80 can be received from the
internet by your server and that there is no other software (such as another
webserver) running on that port. When you have an existing webserver already
listening on port 80 you can use that as well. Or if http traffic is not
possible you can also use DNS based verification, but those go beyond this
guide. Please read the [lego documentation][5] for more details.

We can now update our configuration with the paths of the generated certificate
files (replacing the domain name with the domain name for which you requested a
certificate):

```toml
[[nts-ke-server]]
listen = "[::]:4460"
certificate-chain-path = "/var/lib/lego/certificates/[time.example.com].crt"
private-key-path = "/var/lib/lego/certificates/[time.example.com].key"
```

Finally, restart the ntpd-rs daemon using `systemctl restart ntpd-rs`. Your
server should now be able to handle NTS traffic!

[4]: https://github.com/go-acme/lego
[5]: https://go-acme.github.io/lego/
