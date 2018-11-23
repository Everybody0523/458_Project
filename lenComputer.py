import scapy.all as scapy
import numpy as np
import sys
import matplotlib.pyplot as plt
import grapher as graphMeDaddy

def graph_lengths(infile, pktType):
    pkts = scapy.rdpcap(infile)
    number_packets = len(pkts)
    lens = []
    for packet in pkts:
        if pktType == "TCP":
            if packet.haslayer(scapy.TCP):
                lens.append(len(packet))
        elif pktType == "UDP":
            if packet.haslayer(scapy.UDP):
                lens.append(len(packet))
        elif pktType == "IP":
            if packet.haslayer(scapy.IP) and (not packet.haslayer(scapy.ICMP)):
                lens.append(len(packet))
        elif pktType == "NOT_IP":
            if not packet.haslayer(scapy.IP):
                lens.append(len(packet))
        else:
            print "INVALID pktType!!!"
            return []
    return lens
    

def graph_all(infile):
    TCP_lens = []
    UDP_lens = []
    IP_lens = []
    NOT_IP_lens = []
    for doomPacket in scapy.RawPcapReader(infile):
        packet = scapy.Ether(doomPacket[0])
        wirelen = doomPacket[1][2] 
        if packet.haslayer(scapy.TCP):
            TCP_lens.append(wirelen)
        if packet.haslayer(scapy.UDP):
            UDP_lens.append(wirelen)
        if packet.haslayer(scapy.IP):
            IP_lens.append(wirelen)
        if not packet.haslayer(scapy.IP):
            NOT_IP_lens.append(wirelen)
    return TCP_lens, UDP_lens, IP_lens, NOT_IP_lens
   

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "Wrong number of args"
        sys.exit()
    all_lens = graph_all(sys.argv[1])
    graphMeDaddy.graph_CDF_alt(all_lens, ["TCP", "UDP", "IP", "NOT_IP"], "Packet Sizes", "Packet Size", "Probability", lineLen=1.5) 
    plt.show()


