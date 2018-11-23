import scapy.all as scapy
import numpy as np
import sys
import matplotlib.pyplot as plt
import grapher as graphMeDaddy

def getSizes(infile):
    pkts = scapy.rdpcap(infile)    
    IP_sizes = []
    TCP_sizes = []
    UDP_sizes = []
    for pkt in pkts:
        if (pkt.haslayer(scapy.IP)):
           IP_sizes.append(pkt[scapy.IP].ihl * 4) 
        if (pkt.haslayer(scapy.TCP)):
            TCP_sizes.append(pkt[scapy.TCP].dataofs * 4)
        if (pkt.haslayer(scapy.UDP)):
            UDP_sizes.append(8)
    return IP_sizes, TCP_sizes, UDP_sizes


if __name__ == "__main__":
    arrs = getSizes(sys.argv[1])
    graphMeDaddy.graph_CDF_alt(arrs, ["IP", "TCP", "UDP"], "Header Size", "Size (bytes)", "Observed Probability", 1.7)
    
    
