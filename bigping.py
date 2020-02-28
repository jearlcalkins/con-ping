import argparse
import sys
import ipaddress
from scapy.all import *
from subprocess import Popen
import datetime

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
    for x in xx:
        mine = str(ipaddress.IPv4Address(ipblockstart) + x)
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
                sent_ct += 1
                hostdstip = pkt[IP].dst
                serversrcip = pkt[IP].src
                senttime = pkt.time
                #print(type(pkt.time), dir(pkt.time))
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

    xx = range(iterations)
    for x in xx:
        allhosts = {}
        strtime = datetime.datetime.now()
        p = Popen(['tcpdump', '-i', 'eth0', '-U', '-n', 'icmp', '-w', pcapname], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        (first_ip, last_ip) = ping_starting_here(ipblockstart, ipblocksize)
        print("IPblock:", first_ip, last_ip, len(allhosts), "IPs")
        time.sleep(1)
        p.terminate()
        dumpoutput, dumperrors = p.communicate()
        dumpoutput = dumpoutput.replace('\n',' ')
        dumperrors = dumperrors.replace('\n',' ')
        #print("tcpdump results: errors:", dumperrors, "output:", dumpoutput)
        (begin_send, end_send, sent_ct, rx_ct, slow_ct)  = ana_pcap(pcapname, first_ip, last_ip)
        total_pings_sent += sent_ct
        total_pings_responded += rx_ct
        print("ping response & ratio", rx_ct, sent_ct, str(rx_ct / sent_ct), end='')
        delta_send_time = end_send - begin_send
        print(" send:", delta_send_time, end='')
        print(" block time:", datetime.datetime.now() - strtime)
        print("")

        ipblockstart = str(ipaddress.IPv4Address(ipblockstart) + ipblocksize )

    block_list = allhosts.keys()
    for x in block_list:
        if allhosts[x].reply == False:
            astr = x + "," + "unreachable\n"
        else:
            astr = x + "," + str(allhosts[x].delta) + "\n"
        log.write(astr)
  
    print("total pings sent: ", total_pings_sent, " pings received: ", total_pings_responded, "ratio: ", str(total_pings_responded / total_pings_sent))

def get_pass_variables():

    parser = argparse.ArgumentParser()
    parser.add_argument("ipblockstart", help="IPv4 start e.g. 192.168.0.0", type=str)
    parser.add_argument("ipblocksize", help="block size", type=str)
    parser.add_argument("iterations", help="block iterations", type=str)
    args = parser.parse_args()
    ipblocksize = fixstr(args.ipblocksize)
    iterations = fixstr(args.iterations)
    ipblockstart = args.ipblockstart
    totalipct = ipblocksize * iterations - 1
    ipblockend  = str(ipaddress.IPv4Address(ipblockstart) + totalipct)
    fname = ipblockstart.replace(".","") + "-" + ipblockend.replace(".", "") 
    print(fname, str(ipblocksize), str(iterations), "ip range:", ipblockstart, "-", str(ipaddress.IPv4Address(ipblockstart) + totalipct))
    return (ipblockstart, iterations, ipblocksize, fname)
# sys.exit('early temp exit')

t0 = datetime.datetime.now()
(ipblockstart, iterations, ipblocksize, fname) = get_pass_variables()
logname = fname + ".txt"
log = open(logname, 'w')
allhosts = {}
doit(ipblockstart, iterations, ipblocksize, fname)
log.close()
t1 = datetime.datetime.now()
print("complete .... delta total time", t1 - t0)
