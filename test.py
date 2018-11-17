from scapy.all import *

if __name__ == "__main__":
    packets = rdpcap('traces/sample_pkts')
    nums = [458, 369, 411, 523]
    for num in nums:
        packets[num].show()
     
