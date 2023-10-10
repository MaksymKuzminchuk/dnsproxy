# dnsproxy

Demo dns proxy server written by C and is under development at the moment.
dnsproxy listens for incoming DNS requests on the local interface if requested name is not in blacklist the query forwards to DNS server. 

## Get the code
```
git clone https://github.com/MaksymKuzminchuk/dnsproxy.git
```

## Requirement

dnsproxy is not depend on other libraries

# Build

For Linux users:

`make`

## Usage

Check configure file before run

To run dnsproxy server you need superuser privilege to listen on port 53
you can simple run

`sudo ./dnsproxy` 

## Config file

The default configure is `dnsproxy.cfg` at currect director

Sample congigure file

```
listen_ip = 127.0.0.1
listen_port = 53
dns_ip = 8.8.8.8
blacklist = blacklist.txe
```
## Blacklist

Each DNS name have to start on a new line. It should look like a list
