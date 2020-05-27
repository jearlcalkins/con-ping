#!/home/ec2-user/environments/my_env/bin/python3

# author: jeff calkins
# date: 05-27-2020
# objective:
# concurrectly, single ping a large number of IP addresses, in an IP block or subnet.
# the application starts a tcpdump network capture, for ICMP egress and ingress  
# traffic.  the application builds and sends a block of ICMP request echo to each 
# IP host in the block.  the application waits for 1 second, for echo responses, and 
# all icmp echo responses and timing are recovered from the tcpdump pcap.  the 
# application writes a ping result to a log file, for further analysis

# environment:
# OS: linux or bsd unix
# Network & Firewall: the firewall can't block icmp requests or responses.  a NAT'd 
# IP seems problematic for this application.  if you are using this application behind
# a NAT firewall, the ICMP responses seem to come back to the real IP and will
# not make their way through the firewall.  addressing the ability, to ping from 
# behind a NAT needs to be addressed
# this application spawns tcpdump and needs root (sudo) access to do a network capture
# this tcpdump application is hardwired to capture the 'eth0' nework interface.  if 
# your linux names the primary nework interface, or you need to ping from another 
# interface, you will have to change the tcpdump call
#
# output:
# the ping results are written to a log file with the following naming convention:
# 10.10.0.0-16-1590583392.txt ... where
# the network CIDR address is 10.10.0.0/16 and all IPs in the "network" will be pinged
# the UTC epoch time "time stamp" is 1590583392
#
# future fixes:
# the building of ICMP echo request messages, can be optimized / speeded-up.  
# when running this application on an AWS EC2 t2.micro AMI instance, it takes 
# 00:02:45 to ping a /18 (16,384 IP addresses)
# 00:11:03 to ping a /16 (65,536 IP addresses)

import argparse
import sys
import ipaddress
from scapy.all import *
from subprocess import Popen
import datetime
import time
import math

def fixstr(astr):
    if astr.startswith("0x"):
        aint = int(astr,16)
    else:
        aint = int(astr,10)
    return aint
      
def do_a_ping(da_host):
    send(IP(dst=da_host)/ICMP(), verbose=False)

def ping_starting_here(ipblockstart, ipblocksize):
    global allhosts

    xx = range(ipblocksize)
    first = ipaddress.IPv4Address(ipblockstart)
    for x in xx:
        mine = str(first + x)
        if x == 0:
            first_ip = mine
        allhosts[mine] = Ahost(mine)
        do_a_ping(mine)
    last_ip = mine

    return (first_ip, last_ip)

class Ahost():
    def __init__(self, ip):
        self.ip = ip
        self.respondtime = Decimal('0.000000')
        self.senttime = Decimal('0.000000') 
        self.delta = Decimal('0.000000') 
        self.reply = False

    def add_ping_results(self, respondtime):
        self.respondtime = respondtime
        self.delta = self.respondtime - self.senttime
        self.reply = True

    def add_ping_starts(self, senttime):
        self.senttime = senttime

def ana_pcap(fn_pcap, first_ip, last_ip):
    global allhosts

    a = rdpcap(fn_pcap)
    sent_ct = 0
    rx_ct = 0
    slow_ct = 0
    first_ping = False
    senttime = 0.0

    for i in range(len(a)):
        pkt = a[i]
        if pkt.haslayer(ICMP):
            #print(pkt[IP].src, pkt[IP].dst, pkt[ICMP].type, pkt.time)
            if pkt[ICMP].type == 8:
                hostdstip = pkt[IP].dst
                serversrcip = pkt[IP].src
                senttime = pkt.time
                #print(type(pkt.time), dir(pkt.time))
                #there are scenarios, where a ping response comes in, from an unrelated IP block
                #check if the hoststip is within the network subnet, before attempting to insert
                #stats into the allhosts[], with a hostip index, not belonging to the current network
                #if you were to run this application, at the same time, with two different 
                #network addresses, the "other" addresses would be problematic
                addr4 = ipaddress.ip_address(hostdstip)
                if addr4 in the_network: 
                    sent_ct += 1
                    #print("hostdstip", hostdstip)
                    allhosts[hostdstip].add_ping_starts(senttime)
                    if first_ping == False:
                        begin_send = float(senttime)
                        first_ping = True 
                
            if pkt[ICMP].type == 0:
                rx_ct += 1
                hostdstip = pkt[IP].src
                serversrcip = pkt[IP].dst
                respondtime = pkt.time
                if hostdstip in allhosts.keys():
                    allhosts[hostdstip].add_ping_results(respondtime)
                else:
                    slow_ct += 1

            #print(pkt.show()
    end_send   = float(senttime)

    return (begin_send, end_send, sent_ct, rx_ct, slow_ct)

# ICMP type details
# type: 'echo request'               8
#       'echo reply'                 0
#       'unreachable'                3
#       'time exceeded in-transit'  11 

def doit(ipblockstart, iterations, ipblocksize, fname):

    global allhosts

    pcapname = fname + ".pcap"
    total_pings_sent = 0
    total_pings_responded = 0

    print("doit()", fname, ipblocksize, iterations)
    xx = range(iterations)
    for x in xx:
        allhosts = {}
        strtime = datetime.datetime.now()
        p = Popen(['tcpdump', '-i', 'eth0', '-U', '-n', 'icmp', '-w', pcapname], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        (first_ip, last_ip) = ping_starting_here(ipblockstart, ipblocksize)
        print("IPblock:", first_ip, last_ip, len(allhosts), end='')

        time.sleep(1)
        p.terminate()
        dumpoutput, dumperrors = p.communicate()
        dumpoutput = dumpoutput.replace('\n',' ')
        dumperrors = dumperrors.replace('\n',' ')
        #print("tcpdump results: errors:", dumperrors, "output:", dumpoutput) 
        (begin_send, end_send, sent_ct, rx_ct, slow_ct)  = ana_pcap(pcapname, first_ip, last_ip)
        if os.path.exists(pcapname):
            os.remove(pcapname)

        total_pings_sent += sent_ct
        total_pings_responded += rx_ct

        print(" ping resp & ratio", rx_ct, sent_ct, str(rx_ct / sent_ct))
        delta_send_time = end_send - begin_send
        #print(" send:", delta_send_time, end='')
        #print(" block time:", datetime.datetime.now() - strtime)

        ipblockstart = str(ipaddress.IPv4Address(ipblockstart) + ipblocksize )
        
        ping_ctr = 0
        total_ping_time = 0.0
        block_list = allhosts.keys()
        for x in block_list:
            if allhosts[x].reply == False:
                astr = x + "," + "unreachable\n"
            else:
                astr = x + "," + str(allhosts[x].delta) + "\n"
                ping_ctr += 1
                total_ping_time += float(allhosts[x].delta)
            log.write(astr)
    
    if ping_ctr > 0:
        print("pings:", ping_ctr, "mean:", total_ping_time / ping_ctr, end='')
    else:
        print("pings:", ping_ctr, "mean:", 0.0, end='')

  
    print(" pings tx: ", total_pings_sent, " pings rx: ", total_pings_responded, "ratio: ", str(total_pings_responded / total_pings_sent))

def get_pass_variables():

    parser = argparse.ArgumentParser()
    parser.add_argument("ipblockstart", help="IPv4 start e.g. 192.168.0.0", type=str)
    parser.add_argument("cidr", help="cidr /24 translates to 256 iterations", type=str)
    #parser.add_argument("ipblocksize", help="block size 0x100", type=str)
    args = parser.parse_args()
    ipblocksize = 128            # ipblocksize = fixstr(args.ipblocksize)
    cidr = fixstr(args.cidr)
    cidr_network = args.ipblockstart + "/" + args.cidr
    the_network = ipaddress.ip_network(cidr_network)

    total = 32 - cidr 
    total = 2 ** total 
    iterations = int(total / ipblocksize)
    ipblockstart = args.ipblockstart
    totalipct = ipblocksize * iterations - 1
    ipblockend  = str(ipaddress.IPv4Address(ipblockstart) + total)
    fname = ipblockstart + "-" + str(cidr) 
    print("iteration calcs:", iterations, "total:", iterations, end='') 
    print(" ipblock", ipblocksize, ipblockstart, ipblockend, "totalipct:", totalipct)
    return (ipblockstart, iterations, ipblocksize, fname, the_network )
# sys.exit('early temp exit')

t0 = datetime.datetime.now()
(ipblockstart, iterations, ipblocksize, fname, the_network) = get_pass_variables()
logname = fname + "-" + str(int(time.time())) + ".txt"
log = open(logname, 'w')
allhosts = {}
doit(ipblockstart, iterations, ipblocksize, fname)
log.close()
t1 = datetime.datetime.now()
print("complete .... delta total time", t1 - t0)
