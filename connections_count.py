import sys
from flow import *
import find_flow
import rtt_estimate
import grapher

def num_connections_per_host(tcp_flows):
    # find the number of different connections for each pair of hosts
    # key: (src_ip, dst_ip)
    # value: number of TCP connections open between these hosts
    connections_count = {}
    for flow_key in tcp_flows.keys():
        src_ip, dst_ip, src_port, dst_port = flow_key
        host_pair = src_ip, dst_ip
        if host_pair not in connections_count:
            # new host pair found
            connections_count[host_pair] = 1
        else:
            # new connection for a host pair found
            connections_count[host_pair] += 1
    return connections_count

def three_host_pairs_with_max_connections(connections_count):
    # sort by number of connections to find 3 pairs of hosts with the biggest number of connections
    sorted_connections = []
    for key, count in connections_count.items():
        sorted_connections.append((count, key))
    sorted_connections.sort(reverse=True)
    return sorted_connections[0][1], sorted_connections[1][1], sorted_connections[2][1]

def find_flows_for_host_pair(tcp_flows, src_ip, dst_ip):
    # find all flows for a pair of ip addresses
    # and put them in a list
    flows = []
    for src, dst, src_port, dst_port in tcp_flows.keys():
        if src == src_ip and dst == dst_ip:
            flows.append(tcp_flows[(src, dst, src_port, dst_port)])

    return flows

def estimate_rtt_for_flows(flow_list):
    rtts = []
    relevant_flows = []
    for flow in flow_list:
        mapped_packs = rtt_estimate.map_packets_to_ack(flow)
        EST_arr, OBS_arr = rtt_estimate.compute_estimated_RTT(mapped_packs)
        if len(EST_arr) != 0:
            relevant_flows.append((flow, EST_arr[len(EST_arr) / 2]))
        else:
            for cur_packet in flow.packets:
                print 'seq={0}, ack={1}, len={2}, flag={3}'.format(cur_packet.seq, cur_packet.ack, cur_packet.data_length, format(cur_packet.flags, '#010b'))
    rtts = [rtt for flow, rtt in relevant_flows]
    flows = [flow for flow, rtt in relevant_flows]
    return flows, rtts


def get_start_times_and_rtts(tcp_flows, host1, host2):
    flows = find_flows_for_host_pair(tcp_flows, host1, host2)
    flows, rtts = estimate_rtt_for_flows(flows)

    start_times_to_rtt = []
    for i in range(len(flows)):
        start_times_to_rtt.append((flows[i].first_timestamp, rtts[i]))
    start_times_to_rtt = sorted(start_times_to_rtt)
    start_times = [start_time for start_time, _ in start_times_to_rtt]
    rtts = [rtt for _, rtt in start_times_to_rtt]
    return start_times, rtts


if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        # find all flows and put them in dictionaries
        all_flows, tcp_flows, udp_flows = find_flow.find_flows(pcap)
        connections_count = num_connections_per_host(tcp_flows)
        hosts1, hosts2, hosts3 = three_host_pairs_with_max_connections(connections_count)
        print hosts1, hosts2, hosts3
        start1, rtts1 = get_start_times_and_rtts(tcp_flows, hosts1[0], hosts1[1])
        start2, rtts2 = get_start_times_and_rtts(tcp_flows, hosts2[0], hosts2[1])
        start3, rtts3 = get_start_times_and_rtts(tcp_flows, hosts3[0], hosts3[1])

        #  grapher.graph_RTT_over_time(start1, rtts1, start2, rtts2, start3, rtts3)
        grapher.graph_RTT_over_time(start1, rtts1)
        grapher.graph_RTT_over_time(start2, rtts2)
        grapher.graph_RTT_over_time(start3, rtts3)
