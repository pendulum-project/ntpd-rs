# PTP time sources

## Time source
It is possible to use local PTP devices as time sources for ntpd-rs in addition to the usual NTP sources.  The most common use case for this is virtual machines which use the KVM, Hyper-V, or AWS Nitro hypervisors, all of which supply a PTP Hardware Clock (PHC) device for use by guests (VMs).  At the time of this writing, only KVM PTP devices have been tested.

To configure a KVM guest, simply run:
```sh
sudo modprobe ptp_kvm
```

This will typically create a PTP device file in `/dev` that is immediately available for use:
```
# ls -la /dev/ptp*
crw------- 1 root root 249, 0 Aug 25 13:40 /dev/ptp0
lrwxrwxrwx 1 root root      4 Aug 25 13:40 /dev/ptp_kvm -> ptp0
```

For [AWS instance types which support the ENA PHC](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configure-ec2-ntp.html#connect-to-the-ptp-hardware-clock), place the following in a file in `/etc/modprobe.d/`:
```
options ena phc_enable=1
```

The system must be restarted for the ENA `phc_enable` option to take effect.  The AWS ENA PHC may be used in conjunction with the KVM PHC on supported instances; in such cases you should see both `/dev/ptp0` and `/dev/ptp1` present on the system.

## ntpd-rs configuration
The PTP device can then be added as a time source for ntpd-rs by adding the following to the configuration:
```toml
[[source]]
mode = "ptp"
path = "/dev/ptp0"  # or any other PTP device file; mandatory parameter
delay = 0.00004     # optional, defaults to 0.0; may be used to set the delay to something close to the host's real root delay
interval = 2        # optional, defaults to 0 (1 second)
precision = 1e-7    # optional, defaults to 1 nanosecond
stratum = 1         # optional, defaults to 0; may be used to set the stratum to a value which
                    # makes more sense in the context of the network in which ntpd-rs operates.
```

ntpd-rs is unable to estimate the uncertainty of the timing data from a PTP device. Therefore, you should provide an estimate (corresponding to 1 standard deviation) of this noise yourself through the `precision` field.
