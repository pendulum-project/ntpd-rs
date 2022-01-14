## PTPd setup for testing

PTPd can be used as a ptp master clock for testing. On Ubuntu, it can be installed with
```bash
apt install ptpd
```
You probably wont want to run this continuously as a service, so disable it with
```bash
service ptpd disable
```
Then, to start ptpd, run
```bash
ptpd -n -M -i <INTERFACE>
```
where `<INTERFACE>` is the netwerk interface you want ptpd to use. Here `-n` disables clock adjustment by ptpd, and `-M` ensures that it runs in master mode only.
