import find_flow
import dpkt
import sys

def three_largest_flows(flows_dict, f_value):
    """
    flows_dict: dict of flows
    f_value: function used to compute the "value" of the flow
    return: three flows with largest values as determined by f_value
    """
    all_flows = []
    for key, flow in flows_dict.items():
        value = f_value(flow)
        all_flows.append((value, flow))
    sorted_flows = sorted(all_flows, reverse=True)
    return sorted_flows[0], sorted_flows[1], sorted_flows[2]

def three_largest_flows_packet_number(tcp_flows):
    return three_largest_flows(tcp_flows, lambda flow : len(flow))


def flow_size(flow):
    """
    Return the total size of all packets in the flow in bytes
    """
    byte_size = 0
    for packet in flow:
        byte_size += packet.length
    return byte_size


def three_largest_flows_byte_size(tcp_flows): 
    return three_largest_flows(tcp_flows, lambda flow : flow_size(flow))


def three_largest_flows_duration(tcp_flows): 
    return three_largest_flows(tcp_flows, lambda flow : flow[-1].time - flow[0].time)


def map_packets_to_ack(tcp_flow_objects):
    print 'Mapping acks of flow length=', len(tcp_flow_objects)
    # set of expected acks
    packets_sent_map = {}
    # map of expected acks to a list of actual packet acks
    ack_map = {}
    for i in range(len(tcp_flow_objects)):
        cur_packet = tcp_flow_objects[i]
        #  print cur_packet.seq, cur_packet.ack, cur_packet.length

        if cur_packet.length > 0:
            # packet contains data, thus requires a matching ACK
            # WTF? 
            expected_ack = cur_packet.seq # + cur_packet.length
            packets_sent_map[expected_ack] = None
        if cur_packet.flags & dpkt.tcp.TH_ACK:
            # packet contains ACK, match it with an existing packet
            if cur_packet.ack in packets_sent_map:
                # matched cur_packet as ack of a previous packet
                # since multiple packets can have the same ack number,
                # add all packets with identical acks to a list
                if cur_packet.ack not in ack_map:
                    ack_map[cur_packet.ack] = [cur_packet]
                else:
                    # this case happens when a client sends out
                    # a bunch of packets without waiting for ack
                    ack_map[cur_packet.ack].append(cur_packet)
            else:
                # this case is possible, if a packet that matches
                # this ACK is before the start of the flow captured
                pass

    print 'Number of acknowledged packets', len(ack_map)
    return ack_map


def map_packets_to_ack2(tcp_flow_objects):
    print 'Mapping acks of flow length=', len(tcp_flow_objects)
    # set of expected acks
    packets_sent_map = {}
    # map of expected acks to a list of actual packet acks
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
        # flow1, flow2, flow2 is a tuple
        # first element is number of packets/bytes/duration
        # second element is the flow itself (as a list of FlowPacketTCP objects)
        flow1, flow2, flow3 = three_largest_flows_packet_number(tcp_flows_with_packets)
        map_packets_to_ack(flow1[1])
        print 'Three largest flows by packet number:', flow1[0], flow2[0], flow3[0]
        flow1, flow2, flow3 = three_largest_flows_byte_size(tcp_flows_with_packets)
        print 'Three largest flows by byte size:', flow1[0], flow2[0], flow3[0]
        flow1, flow2, flow3 = three_largest_flows_duration(tcp_flows_with_packets)
         
        print 'Three largest flows by flow duration: {0}, {1}, {2}'.format(flow1[0], flow2[0], flow3[0])

