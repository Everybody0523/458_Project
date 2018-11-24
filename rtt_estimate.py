import find_flow
import dpkt
import sys

def three_largest_flows_packet_number(tcp_flows):
    sorted_flows = []
    for key, flow in tcp_flows.items():
        packet_count = flow[0]
        sorted_flows.append((packet_count, key))
    sorted_flows = sorted(sorted_flows, reverse=True)
    return sorted_flows[0], sorted_flows[1], sorted_flows[2]

def three_largest_flows_byte_size(tcp_flows): 
    sorted_flows = []
    for key, flow in tcp_flows.items():
        byte_size = flow[3]
        sorted_flows.append((byte_size, key))
    sorted_flows = sorted(sorted_flows, reverse=True)
    return sorted_flows[0], sorted_flows[1], sorted_flows[2]

def three_largest_flows_duration(tcp_flows): 
    sorted_flows = []
    for key, flow in tcp_flows.items():
        duration = flow[2] - flow[1]
        sorted_flows.append((duration, key))
    sorted_flows = sorted(sorted_flows, reverse=True)
    return sorted_flows[0], sorted_flows[1], sorted_flows[2]

def map_packets_to_ack(tcp_flow_objects):
    ack_map = {}
    # map each packet to its ack, so that we can estimate RTT
    for i in range(len(tcp_flow_objects)):
        cur_packet = tcp_flow_objects[i]
        if cur_packet.length != 0:
            # contains data (not just ack or other flag)
            # expecting ack for this packet
            ack_map[cur_packet.seq] = None
        # now, match the ack in the current packet to one of the previous packets
        cur_ack = cur_packet.ack
        previous_seq = cur_ack - cur_packet.seq
        if previous_seq in ack_map:
            ack_map[previous_seq] = cur_ack
    print ack_map
        

if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        # find all flows and put them in dictionaries
        all_flows, tcp_flows, udp_flows, all_flows_with_packets, tcp_flows_with_packets, udp_flows_with_packets = find_flow.find_flows(pcap)
        flow1, flow2, flow3 = three_largest_flows_packet_number(tcp_flows)
        print 'Three largest flows by packet number:', flow1[0], flow2[0], flow3[0]
        flow1, flow2, flow3 = three_largest_flows_byte_size(tcp_flows)
        print 'Three largest flows by byte size:', flow1[0], flow2[0], flow3[0]
        flow1, flow2, flow3 = three_largest_flows_duration(tcp_flows)
        print 'Three largest flows by flow duration:', flow1[0], flow2[0], flow3[0]
        #flow1 = 
        #map_packets_to_ack(flow1)
