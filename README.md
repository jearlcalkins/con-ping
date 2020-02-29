# con-ping
concurrent ping (icmp) for large ranges of hosts

###### run environment:
linux with tcpdump
must have sudo or root access
python 3 with these modules: argparse, sys, ipaddress, datetime, subprocess and scapy
ethernet interface: eth0 (you may want to change this hardcoded variable to wlan0, if pinging from your starbucks wifi)

###### a test of tcpdump
You should be able to execute the following tcpdump command as root or sudo, or the application will not work:

```
tcpdump -i eth0 -U -n icmp -w myfav.pcap
```
    
###### recovering ping result times via tcpdump

The tcpdump utility, running as sudo or root, captures a sequence of ICMP 'echo request' packets (aka a ping), destined for a block of IP hosts.
bigping.py utility, currently gives tcpdump 1 second to capture the ICMP 'echo responses' come-back from responding hosts.
The tcpdump utility is stopped, and the tcpdump's pcap file is analyzed for packets sent and packets received, noting how-long it takes for each responding host to reply.
If a host does not replay within the 1 second listening period, no time in the log indicates no response.
If one is pinging hosts 12 timezones away, there is a speed of light latency factor for a 20 million meter, down and back delay of 13ms.
This ignores the refractive index of glass. After throwing in all the router bloat, between here and there, there is an arguement for listening for ping responses, for more than 1 second.
On the otherhand, the 1 second listen time, when pinging a block of 128 IP hosts is a large factor.  Especially when there is a need to ping a /16 , 64,536 unique IPs.

###### running the application

An example:

```python bigping.py 192.168.0.1 0x80 2
```
The application will ping two blocks of IPs.
The block of pings is 128-1 IPs (0x80).
The first IP block is from 192.168.0.1 thru 192.128.0.127, and the second block will finish-up at 192.168.0.255.
The results will end-up in a logfile with the name 19216800-1921680.255.txt
The application will leave you a pcap of the last network capture.
