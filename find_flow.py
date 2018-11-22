import dpkt
import sys
import datetime
import socket
from dpkt.compat import compat_ord
import grapher


def mac_addr(address):
    """Convert a MAC address to a readable/printable string
       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    """Convert inet object to a string
        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def to_percentage(numerator, denominator):
    return (float(numerator) / denominator) * 100

def add_flow_packet(flow_dict, src, dst, src_port, dst_port, time):
    # packets from A to B and from B to A belong to the same flow
    key = (src, dst, src_port, dst_port)
    reverse_key = (dst, src, dst_port, src_port)
    flow = None
    # flow in one direction
    if key in flow_dict:
        flow = flow_dict[key]
    # flow in another direction
    elif reverse_key in flow_dict:
        flow = flow_dict[reverse_key]
        key = reverse_key
    if flow:
        # update existing flow info
        count, first_timestamp, last_timestamp = flow
        time_delta = time - last_timestamp
        # only add to existing flow if packet is less than 90 mins apart
        if time_delta  < datetime.timedelta(minutes=90):
            flow_dict[key] = count + 1, first_timestamp, time
        else:
            print 'flow {0} too far apart'.format(flow)

    else:
        # new flow found
        flow_dict[key] = 1, time, time


def find_flows(pcap):
    all_flows = {}
    tcp_flows = {}
    udp_flows = {}
    # For each packet in the pcap determine if it belongs to a flow
    for timestamp, buf in pcap:

        time = datetime.datetime.utcfromtimestamp(timestamp)
        
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)

        # Make sure the Ethernet data contains an IP packet
        if isinstance(eth.data, dpkt.ip.IP):
            # Now unpack the data within the Ethernet frame (the IP packet)
            # Pulling out src, dst, length, fragment info, TTL, and Protocol
            ip = eth.data
            src = inet_to_str(ip.src)
            dst  = inet_to_str(ip.dst)
            if isinstance(ip.data, dpkt.tcp.TCP):
                # TCP packet
                tcp = ip.data
                src_port = tcp.sport
                dst_port = tcp.dport
                add_flow_packet(tcp_flows, src, dst, src_port, dst_port, time)
                add_flow_packet(all_flows, src, dst, src_port, dst_port, time)
            elif isinstance(ip.data, dpkt.udp.UDP):
                # UDP packet
                udp = ip.data
                src_port = udp.sport
                dst_port = udp.dport
                add_flow_packet(all_flows, src, dst, src_port, dst_port, time)
                add_flow_packet(udp_flows, src, dst, src_port, dst_port, time)

    return all_flows, tcp_flows, udp_flows
    #  for flow in tcp_flows.keys():
        #  src, dst, src_port, src_dst = flow
        #  num_pkts, start_time, end_time = tcp_flows[flow]
        #  duration = end_time - start_time
        #  print '{0}:{2}->{1}:{3} num_pkts={4} duration={5}'.format(src, dst, src_port, src_dst, num_pkts, duration)


def flow_counts(tcp_flows, udp_flows):
    tcp_flow_count = len(tcp_flows)
    udp_flow_count = len(udp_flows)
    total_flow_count = tcp_flow_count + udp_flow_count
    print '{0} TCP flows {1}'.format(tcp_flow_count, to_percentage(tcp_flow_count, total_flow_count))
    print '{0} UDP flows {1}'.format(udp_flow_count, to_percentage(udp_flow_count, total_flow_count))
    total_tcp_count = 0
    for flow in tcp_flows.keys():
        count = tcp_flows[flow][0]
        total_tcp_count += count
    total_udp_count = 0
    for flow in udp_flows.keys():
        count = udp_flows[flow][0]
        total_udp_count += count
    total_packet_count = total_tcp_count + total_udp_count
    print 'Total number of packets in TCP flows: {0} {1}%'.format(total_tcp_count, to_percentage(total_tcp_count, total_packet_count))
    print 'Total number of packets in UDP flows: {0} {1}%'.format(total_udp_count, to_percentage(total_udp_count, total_packet_count))


def flow_durations(flows):
    durations = []
    for flow in flows.keys():
        _, first_timestamp, last_timestamp =  flows[flow]
        timedelta = last_timestamp - first_timestamp
        flow_duration = timedelta.total_seconds()
        durations.append(flow_duration)
    return durations

def flow_packet_counts(flows):
    counts = []
    for flow in flows.keys():
        count, _, _ = flows[flow]
        counts.append(count)
    return counts



def process_flows():
    with open(sys.argv[1], 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        # find all flows and put them in dictionaries
        all_flows, tcp_flows, udp_flows = find_flows(pcap)

        # print info about counts of tcp/udp flows
        flow_counts(tcp_flows, udp_flows)

        # find durations of flows
        all_durations = flow_durations(all_flows)
        tcp_durations = flow_durations(tcp_flows)
        udp_durations = flow_durations(udp_flows)

        # graph CDF of durations
        grapher.graph_CDF_alt([all_durations, tcp_durations, udp_durations], ['All', 'TCP', 'UDP'], 'CDF of flow durations', 'duration (seconds)', 'probability')

        # find packet counts of flows
        all_counts = flow_packet_counts(all_flows)
        tcp_counts = flow_packet_counts(tcp_flows)
        udp_counts = flow_packet_counts(udp_flows)
        # graph CDF of packet counts
        grapher.graph_CDF_alt([all_counts, tcp_counts, udp_counts], ['All', 'TCP', 'UDP'], 'CDF of flow packet sizes', 'number of packets in a flow', 'probability')



if __name__ == '__main__':
    process_flows()
