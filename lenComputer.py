import scapy.all as scapy
import numpy as np
import sys
import matplotlib.pyplot as plt

def graphCDF(pktLens):
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
    


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print "Wrong number of args"
        sys.exit()
    lens = graph_lengths(sys.argv[1], sys.argv[2])
    print len(lens)
    graphCDF(lens)
