# Setting up an NTP server

By default, ntpd-rs only acts as an ntp client, and doesn't serve time on any
network interface. To enable ntpd-rs as a server, the following can be added to
the configuration:
```toml
[[server]]
listen = "0.0.0.0:123"
```
This will cause ntpd-rs to listen on all network interfaces on udp port 123 for
ntp client requests. If you only want to listen on a specific network
interface, change `0.0.0.0` to the ip address of that interface.

You can now configure a different machine to use your new server by adding to
its configuration:
```toml
[[source]]
mode = "server"
address = "<your server ip>:123"
```

## Limiting access
If you only want specific ip addresses to be able to access the server, you can
configure a list of allowed clients through the allowlist mechanism. For this,
edit the server configuration to look like:
```toml
[[server]]
listen = "0.0.0.0:123"
[server.allowlist]
filter = ["<allowed ipv4 1>/32", "<allowed ipv4 2>/32", "<allowed ipv6 1>/128"]
action = "ignore"
```
When configured this way, your server will only respond to the listed ip
addresses. You can allow entire subnets at a time by specifying the size of the
subnet instead of 32 or 128 after the slash.

## Adding your server to the NTP pool

If your ntp server has a public IP address, you can consider making it
available as part of the [NTP pool](https://www.ntppool.org). Please note that
this can have significant long-term impact in terms of NTP traffic to that
particular IP address. Please read [the join instructions](https://www.ntppool.org/en/join.html)
carefully before joining the pool.

