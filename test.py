from scapy.all import *


def getLengthNonIP():
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


if __name__ == "__main__":
    packets = rdpcap('traces/sample_pkts')
    nums = [458, 369, 411, 523, 901, 1, 17, 55]
    #for num in nums:
    #    packets[num].show()
    lens = []
    counter = 0
    nonIPs = 0
    for p in packets:
        if ((IP in p)):
            p.show()
            print counter
            print "---------------------------------------------------"
            nonIPs += 1
            lens.append(len(IP(p)))
        counter += 1
    print "Found " + str(nonIPs) + " IP packets"
    print lens
     
