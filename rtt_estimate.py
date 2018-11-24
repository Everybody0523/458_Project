import find_flow
import dpkt
import sys

def three_largest_flows_packet_number(tcp_flows):
    sorted_flows = []
    for key, flow in tcp_flows.items():
        packet_count = len(flow)
        sorted_flows.append((packet_count, key))
    sorted_flows = sorted(sorted_flows, reverse=True)
    return sorted_flows[0], sorted_flows[1], sorted_flows[2]

def three_largest_flows_byte_size(tcp_flows): 
    sorted_flows = []
    for key, flow in tcp_flows.items():
        byte_size = 0
        for packet in flow:
            byte_size += packet.length
        sorted_flows.append((byte_size, key))
    sorted_flows = sorted(sorted_flows, reverse=True)
    return sorted_flows[0], sorted_flows[1], sorted_flows[2]

def three_largest_flows_duration(tcp_flows): 
    sorted_flows = []
    for key, flow in tcp_flows.items():
        duration = flow[-1].time - flow[0].time
        sorted_flows.append((duration, key))
    sorted_flows = sorted(sorted_flows, reverse=True)
    return sorted_flows[0], sorted_flows[1], sorted_flows[2]

def map_packets_to_ack(tcp_flow_objects):
    print 'Mapping acks of flow length=', len(tcp_flow_objects)
    ack_map = {}
    # first packet in the flow 
    last_A_seq = tcp_flow_objects[0].seq
    last_B_seq = None # can't set right away
    A_ip = tcp_flow_objects[0].src
    B_ip = tcp_flow_objects[0].dst
    for i in range(len(tcp_flow_objects)):
        cur_packet = tcp_flow_objects[i]
        if last_B_seq is None and cur_packet.src == B_ip:
            # initialize last B seq
            last_B_seq = cur_packet.seq

        if cur_packet.flags ^ dpkt.tcp.TH_ACK != 0:
            # flags xor ack will produce zero if only ack is set
            # otherwise, packet contains data (not just ack)
            previous_seq = None
            if cur_packet.src == A_ip:
                previous_seq = last_A_seq
            else:
                previous_seq = last_B_seq

            # expecting ack for this packet
            # of the value previous_seq + bytes in current packet
            ack_map[cur_packet.seq] = previous_seq + cur_packet.length, cur_packet.seq
        else:
            # packet contains just ACK, 
            print cur_packet.seq, cur_packet.ack, cur_packet.length
        # now, match the ack in the current packet to one of the previous packets
        cur_ack = cur_packet.ack
        previous_seq = cur_ack - cur_packet.seq
        if previous_seq in ack_map:
            ack_map[previous_seq] = cur_ack
        

if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        # find all flows and put them in dictionaries
        all_flows, tcp_flows, udp_flows, all_flows_with_packets, tcp_flows_with_packets, udp_flows_with_packets = find_flow.find_flows(pcap)
        flow1, flow2, flow3 = three_largest_flows_packet_number(tcp_flows_with_packets)
        map_packets_to_ack(tcp_flows_with_packets[flow1[1]])
        print 'Three largest flows by packet number:', flow1[0], flow2[0], flow3[0]
        flow1, flow2, flow3 = three_largest_flows_byte_size(tcp_flows_with_packets)
        print 'Three largest flows by byte size:', flow1[0], flow2[0], flow3[0]
        flow1, flow2, flow3 = three_largest_flows_duration(tcp_flows_with_packets)
        print 'Three largest flows by flow duration:', flow1[0], flow2[0], flow3[0]
