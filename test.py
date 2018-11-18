from scapy.all import *
import numpy as np
import matplotlib.pyplot as plt


def getLengthNonIP():
    packets = rdpcap('traces/sample_pkts')
    lens = []
    counter = 0
    nonIPs = 0
    for p in packets:
        if (not (IP in p)):
            p.show()
            print counter
            print "---------------------------------------------------"
            nonIPs += 1
            lens.append(len(ARP(p)))
        counter += 1
    print "Found " + str(nonIPs) + " non-IP packets"
    print lens


def getLengthIP():
    packets = rdpcap('traces/sample_pkts')
    lens = []    
    for p in packets:
        if (IP in p):
            lens.append(len(IP(p)))
    return lens 


def getLengthTCP():
    packets = rdpcap('traces/sample_pkts')
    lens = []    
    for p in packets:
        if (TCP in p):
            lens.append(len(TCP(p)))
    return lens 
       

def getLengthUDP():
    packets = rdpcap('traces/sample_pkts')
    lens = []    
    for p in packets:
        if (UDP in p):
            lens.append(len(UDP(p)))
    return lens 



if __name__ == "__main__":
    lengths = getLengthUDP()
    # evaluate the histogram
    values, base = np.histogram(lengths, bins=40)
    #evaluate the cumulative
    cumulative = np.cumsum(values)
    # plot the cumulative function
    plt.plot(base[:-1], cumulative, c='blue')
    plt.show()

