# Getting started with ntpd-rs

Ntpd-rs is an implementation of the NTP protocol. It aims to synchronize your system's clock to time received from the internet. It can also, when [configured as server](server-setup.md), provide time to other machines on the network.

## Installation

Installation instructions for your system can be found in the [installation guide](installation.md). For first time users, we strongly recommend using either your OS package repository packages, or the packages we redistribute. If you have installed ntpd-rs from source, and you have installed files in different locations than the default, you may need to modify the instructions below.

## Checking the synchronization.

The default configuration for ntpd-rs  sets it up to synchronize with four servers chosen from [the NTP pool](https://www.ntppool.org). We can check its synchronization status using:
```sh
ntp-ctl status
```

If everything is installed and working correctly this will display information looking like:
```
Synchronization status:
Dispersion: 0.000055s, Delay: 0.005241s
Desired poll interval: 16s
Stratum: 2

Sources:
ntpd-rs.pool.ntp.org:123 (1): +0.000051±0.000096(±0.006731)s
    pollinterval: 16s, missing polls: 0
ntpd-rs.pool.ntp.org:123 (2): -0.000218±0.000127(±0.004499)s
    pollinterval: 16s, missing polls: 0
ntpd-rs.pool.ntp.org:123 (3): -0.000233±0.000082(±0.007134)s
    pollinterval: 16s, missing polls: 0
ntpd-rs.pool.ntp.org:123 (4): +0.000368±0.000108(±0.005226)s
    pollinterval: 16s, missing polls: 0

Servers:

```

The first section gives some general information on the time synchronization. The dispersion is a measure for how precise it thinks the local time is, and the delay is a measure of how long the communication delay to the best (most precise) server is. Desired poll interval indicates how often it currently wants to know the time from downstream servers, and stratum indicates how many servers are between us and a reference source of time such as an atomic clock or GPS receiver. Stratum will always be at least 2 when configured as a client using only sources from across the internet.

Next, we get information on each of the time sources, showing the measured offset and the uncertainty on that, as well as (between brackets) the delay to the server. We also show the poll interval used for that particular source. This can be different from the desired poll interval if a server requests us to do fewer queries. Finally, missing polls gives an indication of how many times we have tried to poll the server since last getting a time measurement for it.

The final section is empty, but if we were running a server, it would show statistics on how often the server is used.

## Configuring a custom time source

The sources ntpd-rs uses to get the current time can be configured in the `/etc/ntpd-rs/ntp.toml` configuration file. Suppose that, in addition to the sources from the NTP pool, we also always want to use two sources from the [time.nl](https://time.nl) pool. To do this, we add the following lines to the configuration file:
```toml
[[source]]
mode = "pool"
address = "ntp.time.nl"
count = 2
```

After restarting the daemon (using `sudo systemctl restart ntpd-rs` if you are using Linux) and waiting a bit for it to synchronize, the status now looks like
```
Synchronization status:
Dispersion: 0.000106s, Delay: 0.005310s
Desired poll interval: 16s
Stratum: 2

Sources:
ntp.time.nl:123 (1): -0.000007±0.000117(±0.005710)s
    pollinterval: 16s, missing polls: 0
ntp.time.nl:123 (2): +0.000169±0.000163(±0.005310)s
    pollinterval: 16s, missing polls: 0
ntpd-rs.pool.ntp.org:123 (3): -0.000556±0.000142(±0.004329)s
    pollinterval: 16s, missing polls: 0
ntpd-rs.pool.ntp.org:123 (4): +0.001018±0.000088(±0.005182)s
    pollinterval: 16s, missing polls: 0
ntpd-rs.pool.ntp.org:123 (5): -0.000682±0.000130(±0.004179)s
    pollinterval: 16s, missing polls: 0
ntpd-rs.pool.ntp.org:123 (6): +0.001074±0.000113(±0.005314)s
    pollinterval: 16s, missing polls: 0

Servers:

```
where we see the two servers from `time.nl` added to the list of sources.

## Where to go from here

You now have a working NTP client, can check its status, and if desired modify
the sources it uses for time. There are multiple directions to go from here.

If you want more certainty around the authenticity of your time sources, you
can take a look at [using NTS](TODO).

Setting up your own time server is explained in our [server setup guide](server-setup.md).

When operating ntpd-rs as part of a larger critical system, you may also be
interested in our [guidance on hardening ntpd-rs](security-guidance.md).
