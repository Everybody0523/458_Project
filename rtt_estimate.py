import find_flow
import dpkt
import sys
import grapher as graph_me_daddy

ALPHA = 0.125
BETA = 0.25

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
    return three_largest_flows(tcp_flows, lambda flow : flow.num_packets)


def three_largest_flows_byte_size(tcp_flows): 
    return three_largest_flows(tcp_flows, lambda flow : flow.num_bytes)


def three_largest_flows_duration(tcp_flows): 
    return three_largest_flows(tcp_flows, lambda flow : flow.flow_duration())


def map_packets_to_ack(tcp_flow):
    print 'Mapping acks in the flow of length=', tcp_flow.num_packets
    # set of expected acks
    packets_sent_map = {}

    # for detecting retransmissions
    retransmits = {}
    max_rev_seq = 0
    max_fwd_seq = 0
    
    packets_and_their_acks = []
    for i in range(tcp_flow.num_packets):
        cur_packet = tcp_flow.packets[i]
        #print 'seq={0}, ack={1}, len={2}, flag={3}'.format(cur_packet.seq, cur_packet.ack, cur_packet.data_length, format(cur_packet.flags, '#010b'))
        if cur_packet.data_length > 0 or cur_packet.flags & dpkt.tcp.TH_ACK != cur_packet.flags and cur_packet.flags & dpkt.tcp.TH_RST != cur_packet.flags:
            # packet contains data, thus may require a matching ACK
            # Except not really, see the Cumulative ACK case in the slides :D
            # But if that happens we ignore the first packet for the purpose of estimating RTT I guess
            # Or if the flow cuts off the ACK
            bigger_than_prev = False

            if cur_packet.flags & dpkt.tcp.TH_SYN or cur_packet.flags & dpkt.tcp.TH_FIN:
                expected_ack = cur_packet.seq + 1
            else:
                expected_ack = cur_packet.seq + cur_packet.data_length

            src = tcp_flow.src
            src_port = tcp_flow.src_port
            if cur_packet.rev:
                src = tcp_flow.dst
                src_port = tcp_flow.dst_port
                bigger_than_prev = cur_packet.seq > max_rev_seq
            else:
                bigger_than_prev = cur_packet.seq > max_fwd_seq
            pkt_tup = (cur_packet.seq, cur_packet.ack, cur_packet.data_length, cur_packet.time)
            #  if not bigger_than_prev:
                #  print 'NOT bigger than previous:', cur_packet.seq, max_rev_seq, max_fwd_seq

            chk_for_retrans = (cur_packet.seq, src, src_port)
            if chk_for_retrans not in retransmits and (True or bigger_than_prev):
                # Not a retransmission
                retransmits[chk_for_retrans] = 1 #Dummy value in dict 
                packets_sent_map[expected_ack] = pkt_tup
            else:
                # This is a retransmission, just drop the packet from the dict 
                #  print "dropped"
                if expected_ack in packets_sent_map:
                    del packets_sent_map[expected_ack]

        if cur_packet.flags & dpkt.tcp.TH_ACK:
            # packet contains ACK, match it with an existing packet
            if cur_packet.ack in packets_sent_map:
                # matched cur_packet as ack of a previous packet
                
                # Value of the dict is the sequence number and time
                # of the packet it is an ack of
                temp_tup = (cur_packet.seq, cur_packet.ack, cur_packet.data_length, cur_packet.time)
                packet_and_its_ack = (temp_tup, packets_sent_map[cur_packet.ack])
                packets_and_their_acks.append(packet_and_its_ack)
                """
                if cur_packet.ack not in ack_map:
                    ack_map[cur_packet.ack] = [cur_packet]
                else:
                    # this case happens when a client sends out
                    # a bunch of packets without waiting for ack
                    ack_map[cur_packet.ack].append(cur_packet)
                """
            else:
                # this case is possible, if a packet that matches
                # this ACK is before the start of the flow captured
                pass

    print 'Number of acknowledged packets', len(packets_and_their_acks)
    return packets_and_their_acks 


def compute_estimated_RTT(mapped_packs_to_acks):
    SRTT = None
    EST_arr = [] 
    OBS_arr = []
    for pair in mapped_packs_to_acks:
        sample_RTT = pair[0][3] - pair[1][3]
        if SRTT is None:
            SRTT = sample_RTT.total_seconds() * 1000
            print sample_RTT
            print SRTT
        else:
            SRTT = ((1 - ALPHA) * SRTT) + ALPHA * sample_RTT.total_seconds() * 1000
        EST_arr.append(SRTT)
        OBS_arr.append(sample_RTT.total_seconds() * 1000)
    return EST_arr, OBS_arr
               
def graph_three_largest(flow1, flow2, flow3, name):
    flows = [flow1, flow2, flow3]
    count = 1 
    for flow in flows:
        mapped_packs = map_packets_to_ack(flow[1])
        EST_arr, OBS_arr = compute_estimated_RTT(mapped_packs)
        graph_me_daddy.graph_RTTs(EST_arr, OBS_arr, "Largest By " + name, count)
        count += 1
 

if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        # find all flows and put them in dictionaries
        all_flows, tcp_flows, udp_flows = find_flow.find_flows(pcap)
        # flow1, flow2, flow2 is a tuple
        # first element is number of packets/bytes/duration
        # second element is the flow itself (as a list of FlowPacketTCP objects)
        flow1, flow2, flow3 = three_largest_flows_packet_number(tcp_flows)
        print 'Three largest flows by packet number: {0}, {1}, {2}'.format(flow1[0], flow2[0], flow3[0])
        graph_three_largest(flow1, flow2, flow3, 'packet number')
        flow1, flow2, flow3 = three_largest_flows_byte_size(tcp_flows)
        print 'Three largest flows by byte size:', flow1[0], flow2[0], flow3[0]
        graph_three_largest(flow1, flow2, flow3, 'byte size')
        flow1, flow2, flow3 = three_largest_flows_duration(tcp_flows)
        print 'Three largest flows by duration:', flow1[0], flow2[0], flow3[0]
        graph_three_largest(flow1, flow2, flow3, 'duration')
        """
        count = 0
        for pair in mapped_packs:
            #First tuple is the acknowledgement, the second is the one BEING acknowledged
            sample = pair[0][3] - pair[1][3]
            if count % 500 == 0:
                print "Packet Time:{1} Ack Time:{0} Sample RTT:{2}".format(pair[0][3], pair[1][3], sample)
            count += 1
        """
        """
        flow1, flow2, flow3 = three_largest_flows_byte_size(tcp_flows)
        print 'Three largest flows by byte size:', flow1[0], flow2[0], flow3[0]
        flow1, flow2, flow3 = three_largest_flows_duration(tcp_flows)
         
        print 'Three largest flows by flow duration: {0}, {1}, {2}'.format(flow1[0], flow2[0], flow3[0])
        """
