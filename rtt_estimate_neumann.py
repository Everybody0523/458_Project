import find_flow
import dpkt
import sys
import rtt_estimate

def match_packets_with_ackpack(tcp_flow):
    # Key: A packet
    # Value: The packet that acknowledges the packet that is the key
    match_dict = {}

    # Key: A tuple, containing the src, src_port, and the acknowledgement
    # number
    # Value: The packet itself
    ack_dict = {}
    for pkt in tcp_flow:
        temp_tup = (pkt.src, pkt.src_port, pkt.ack) 
        if temp_tup not in ack_dict:
            ack_dict[temp_tup] = pkt
    
    for pkt in tcp_flow:
        temp_tup = (pkt.dst, pkt.dst_port, pkt.seq)
        count = 0
        if temp_tup in ack_dict:
            match_dict[pkt] = ack_dict[temp_tup]
            count += 1
    print count
    print len(tcp_flow)
    print len(ack_dict)
    return match_dict
        

if __name__ == "__main__":
    with open(sys.argv[1], 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        # find all flows and put them in dictionaries
        # key is a tuple (src ip, dst ip, src port, dst port)
        # value is the object of type Flow (flow.py)
        all_flows, tcp_flows, udp_flows = find_flow.find_flows(pcap)

        # flow1, flow2, flow2 is a tuple
        # first element is number of packets/bytes/duration
        # second element is (value sorted by, Flow object)
        flow1, flow2, flow3 = rtt_estimate.three_largest_flows_packet_number(tcp_flows_with_packets)
        match_dict = match_packets_with_ackpack(flow1[1])
