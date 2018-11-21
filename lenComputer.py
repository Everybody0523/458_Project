import scapy.all as scapy
import numpy as np
import sys
import matplotlib.pyplot as plt

def graph_CDF(pktLens):
    values, base = np.histogram(pktLens, bins=40)
    cumulative = np.cumsum(values)
    plt.plot(base[:-1], cumulative, c='blue')
    plt.show()     


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
            if packet.haslayer(scapy.IP):
                lens.append(len(packet))
        elif pktType == "NOT_IP":
            if not packet.haslayer(scapy.IP):
                lens.append(len(packet))
        else:
            print "INVALID pktType!!!"
            return []
    return lens
    

def graph_all(infile):
    pkts = scapy.rdpcap(infile)
    number_packets = len(pkts)
    TCP_lens = []
    UDP_lens = []
    IP_lens = []
    NOT_IP_lens = []
    for packet in pkts:
        if packet.haslayer(scapy.TCP):
            TCP_lens.append(len(packet))
        if packet.haslayer(scapy.UDP):
            UDP_lens.append(len(packet))
        if packet.haslayer(scapy.IP):
            IP_lens.append(len(packet))
        if not packet.haslayer(scapy.IP):
            NOT_IP_lens.append(len(packet))
    return TCP_lens, UDP_lens, IP_lens, NOT_IP_lens
   

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "Wrong number of args"
        sys.exit()
    all_lens = graph_all(sys.argv[1])
    fig, ax = plt.subplots(figsize=(8, 4))
    n, bins, patches = ax.hist(all_lens[0], 100, cumulative=True, density=True, histtype="step", label="TCP")
    n, bins, patches = ax.hist(all_lens[1], 100, cumulative=True, density=True, histtype="step", label="UDP")
    n, bins, patches = ax.hist(all_lens[2], 100, cumulative=True, density=True, histtype="step", label="IP")
    n, bins, patches = ax.hist(all_lens[3], 100, cumulative=True, density=True, histtype="step", label="Not_IP")
    ax.grid(True)
    ax.legend(loc='right')
    ax.set_title('Cumulative step histograms')
    ax.set_xlabel('Annual rainfall (mm)')
    ax.set_ylabel('Likelihood of occurrence')

    plt.show()


