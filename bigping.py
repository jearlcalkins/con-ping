import ipaddress
from scapy.all import *
from subprocess import Popen
import datetime


def do_a_ping(da_host):
    send(IP(dst=da_host)/ICMP(), verbose=False)

def ping_starting_here(ip_blockstart, ping_block_size):
    xx = range(ping_block_size)
    for x in xx:
        mine = str(ipaddress.IPv4Address(ip_blockstart) + x)
        if x == 0:
            first_ip = mine
        allhosts[mine] = Ahost(mine)
        do_a_ping(mine)
    last_ip = mine
    return (first_ip, last_ip)

class Ahost():
    def __init__(self, ip):
        self.ip = ip
        self.respondtime = float(0)
        self.senttime = float(0) 
        self.delta = float(0) 

    def add_ping_results(self, respondtime):
        self.respondtime = respondtime
        self.delta = self.respondtime - self.senttime

    def add_ping_starts(self, senttime):
        self.senttime = senttime

def ana_pcap(fn_pcap, first_ip, last_ip):
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
                allhosts[hostdstip].add_ping_starts(senttime)
                if first_ping == False:
                    begin_send = float(senttime)
                    first_ping = True 
                
                #print(sent_ct, "*ping start time object version:", allhosts[hostdstip].senttime)
            if pkt[ICMP].type == 0:
                rx_ct += 1
                hostdstip = pkt[IP].src
                serversrcip = pkt[IP].dst
                respondtime = pkt.time
                if hostdstip in allhosts.keys():
                    allhosts[hostdstip].add_ping_results(respondtime)
                    #print(rx_ct, "** ", hostdstip, allhosts[hostdstip].senttime, allhosts[hostdstip].respondtime)
                    #print("now the ping_time", allhosts[hostdstip].ping_time() )
                    a_str = hostdstip + "," + str(allhosts[hostdstip].delta) + "\n"
                    log.write(a_str)
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

starbucksip = '4.34.46.0'
starbucksip = '4.34.0.0'
chartersip = '142.254.0.0'

ip_blockstart = chartersip 
ping_block_size = 0x100
log = open('log_hammer.txt', 'w')
total_pings_sent = 0
total_pings_responded = 0

xx = range(0x100)
for x in xx:
    allhosts = {}
    print(datetime.datetime.now())
    p = Popen(['tcpdump', '-i', 'eth0', '-U', '-n', 'icmp', '-w', 'cap.pcap'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    (first_ip, last_ip) = ping_starting_here(ip_blockstart, ping_block_size)
    print("first last IPs in block:", first_ip, last_ip, "total of:", len(allhosts))
    time.sleep(1)
    p.terminate()
    dumpoutput, dumperrors = p.communicate()
    dumpoutput = dumpoutput.replace('\n',' ')
    dumperrors = dumperrors.replace('\n',' ')
    print("tcpdump results: errors:", dumperrors, "output:", dumpoutput)
    (begin_send, end_send, sent_ct, rx_ct, slow_ct)  = ana_pcap("cap.pcap", first_ip, last_ip)
    total_pings_sent += sent_ct
    total_pings_responded += rx_ct
    print("ping response & ratio", rx_ct, sent_ct, str(rx_ct / sent_ct), "too slow: ", slow_ct, end='')
    delta_send_time = end_send - begin_send
    print(" time to build-send the block", str(delta_send_time))
    print("")

    ip_blockstart = str(ipaddress.IPv4Address(ip_blockstart) + ping_block_size )

print("pings sent: ", total_pings_sent, " pings received: ", total_pings_responded, "ratio: ", str(total_pings_responded / total_pings_sent))

log.close()
