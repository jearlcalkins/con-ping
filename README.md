# con-ping
concurrent ping (icmp) for large ranges of hosts

##### run environment:
AWS AMI linux on t2.micro
tcpdump installed
sudo or root access
python 3.6 with these modules: argparse, sys, ipaddress, datetime, subprocess and scapy
ethernet interface: eth0 
other linux or bsd unix's may use a different interface name. if so, the hardcoded tcpdump call, will need to be changed.

##### rough install directions #####
be careful with python3 environment, and a good corresponding pip3 install.  
```
sudo yum update -y
sudo yum upgrade -y
sudo yum install python36 -y
sudo yum install tcpdump -y
curl -O https://bootstrap.pypa.io/get-pip.py
python3 get-pip.py --user

pip install numpy
pip install pandas
pip install scapy
pip install matplotlib
pip install ipaddress
```

##### needed updates to this code???:
1) change the #! line, the first line of bigping.py, to use your server's python location.

##### a test of tcpdump
You should be able to execute the following tcpdump command as root or sudo, or the application will not work:

```
tcpdump -i eth0 -U -n icmp -w myfav.pcap
```
    
##### recovering ping result times via tcpdump

The tcpdump utility, running as sudo or root, captures a sequence of ICMP 'echo request' packets (aka a ping), destined for a block of IP hosts.
bigping.py utility, currently gives tcpdump 1 second to capture the ICMP 'echo responses' come-back from responding hosts.
The tcpdump utility is stopped, and the tcpdump's pcap file is analyzed for packets sent and packets received, noting how-long it takes for each responding host to reply.
If a host does not replay within the 1 second listening period, no time in the log indicates no response.  Changing the listen period from 1 second to 2 seconds time.sleep(2) may capture more icmp responses, especially those, on the other side of the globe.  however, the elapsed time, necessary to ping a block will become longer.


If one is pinging hosts 12 timezones away, there is a speed of light latency factor for a 20 million meter, down and back delay of 13ms.
This ignores the degradation of the speed of light, through fiber with a glass refractive index. After throwing in all the router bloat, between here and there, there is an arguement for listening for ping responses, for more than 1 second.
On the otherhand, the 1 second listen time, when pinging a block of 128 IP hosts is a large factor.
Especially when there is a need to ping a /16 , 64,536 unique IPs.  

Another consideration is; how many pings you burst at once.  The ICMP 'echo request' packets are small, but they have to be carried to their destination and the host NIC has to respond with an 'echo'.
That is, if the host is even configured to provide a ping response.
At some point, an ISP may not tolerate your ping bursts and they may block you.
The application is hardcoded to ping / burst a block of 128 hosts.
In some situations, I'm pinging an entire /16 and that effort alone, may irritate a network admin. I don't know at what level, network admins, will intervene and block your pings.

##### running the application

An example:

1. The first IP block starts at 192.168.0.0
2. A cidr number e.g. 24 will ping 256 IPs, starting with the above IP block

```
python bigping.py 192.168.0.1 24
```

Because of the hardcoded 0x80 (128) blocksize, the application will start with 192.168.0.0 base address and ping two blocks; the application will ping 192.168.0.0 thru 192.168.0.255

The application results will leave you a logfile with the name 192.168.0.0-24-1590597359.txt
This results snippet is a ping results from another base IP address:
```
...
4.34.51.0,unreachable
4.34.51.1,0.036774
4.34.51.2,0.037131
4.34.51.3,unreachable
...
```
