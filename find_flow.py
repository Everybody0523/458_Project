import dpkt
import sys
import datetime
import socket
from dpkt.compat import compat_ord
import grapher
from flow import FlowPacketTCP, Flow, FlowPacket

last_timestamp = None

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

def add_flow_packet(flow_dict, src, dst, src_port, dst_port, new_packet):
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
        new_packet.rev = True

    if flow:
        # update existing flow info
        time_delta = new_packet.time - flow.packets[-1].time
        # only add to existing flow if packet is less than 90 mins apart
        if time_delta  < datetime.timedelta(minutes=90):
            flow.add_packet(new_packet)
        else:
            print 'flow {0} too far apart'.format(flow)
    else:
        # new flow found
        flow_dict[key] = Flow(src, dst, src_port, dst_port)
        flow_dict[key].add_packet(new_packet)

def find_flows(pcap):
    global last_timestamp
    all_flows = {}
    tcp_flows = {}
    udp_flows = {}
    # For each packet in the pcap determine if it belongs to a flow
    for timestamp, buf in pcap:
        time = datetime.datetime.utcfromtimestamp(timestamp)
        last_timestamp = time
        
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        eth_hdr_length = 18

        # Make sure the Ethernet data contains an IP packet
        if isinstance(eth.data, dpkt.ip.IP):
            # Now unpack the data within the Ethernet frame (the IP packet)
            # Pulling out src, dst, length, fragment info, TTL, and Protocol
            ip = eth.data
            src = inet_to_str(ip.src)
            dst  = inet_to_str(ip.dst)
            # length is the length of the entire IP packet, including the header
            total_length = ip.len + eth_hdr_length
            # just the header length in bytes (ip.hl is the number of 32-bit words)
            ip_hdr_length = ip.hl * 4
            if isinstance(ip.data, dpkt.tcp.TCP):
                # TCP packet
                tcp = ip.data
                src_port = tcp.sport
                dst_port = tcp.dport
                seq = tcp.seq
                ack = tcp.ack
                tcp_hdr_length = tcp.off * 4
                new_packet = FlowPacketTCP(time, total_length, eth_hdr_length, ip_hdr_length, tcp_hdr_length, seq, ack, tcp.flags)
                add_flow_packet(tcp_flows, src, dst, src_port, dst_port, new_packet)
                general_new_packet = FlowPacket(time, total_length, eth_hdr_length, ip_hdr_length, tcp_hdr_length)
                add_flow_packet(all_flows, src, dst, src_port, dst_port, general_new_packet)
            elif isinstance(ip.data, dpkt.udp.UDP):
                # UDP packet
                udp = ip.data
                src_port = udp.sport
                dst_port = udp.dport
                # udp header is always 8 bytes
                udp_hdr_length = 8
                new_packet = FlowPacket(time, total_length, eth_hdr_length, ip_hdr_length, udp_hdr_length)
                add_flow_packet(all_flows, src, dst, src_port, dst_port, new_packet)
                add_flow_packet(udp_flows, src, dst, src_port, dst_port, new_packet)

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
        count = tcp_flows[flow].num_packets
        total_tcp_count += count
    total_udp_count = 0
    for flow in udp_flows.keys():
        count = udp_flows[flow].num_packets
        total_udp_count += count
    total_packet_count = total_tcp_count + total_udp_count
    print 'Total number of packets in TCP flows: {0} {1}%'.format(total_tcp_count, to_percentage(total_tcp_count, total_packet_count))
    print 'Total number of packets in UDP flows: {0} {1}%'.format(total_udp_count, to_percentage(total_udp_count, total_packet_count))
    print 'Average number of packets in TCP flow: {0}'.format(float(total_tcp_count) / tcp_flow_count)
    print 'Average number of packets in UDP flow: {0}'.format(float(total_udp_count) / udp_flow_count)


def flow_durations(flows):
    durations = []
    for flow in flows.keys():
        flow_duration = flows[flow].flow_duration()
        durations.append(flow_duration)
    return durations

def flow_packet_counts(flows):
    counts = []
    for flow in flows.keys():
        count = flows[flow].num_packets
        counts.append(count)
    return counts

def flow_byte_sizes(flows):
    byte_sizes = []
    for flow in flows.keys():
        # flow_size is the total size of all flow packets, including all headers
        flow_size = flows[flow].num_bytes + flows[flow].total_hdr_size
        byte_sizes.append(flow_size)
    return byte_sizes

def flow_interpacket_arrival_times(flows):
    interpacket_times = []
    for flow in flows.keys():
        flow_packets = flows[flow].packets
        for i in range(1, len(flow_packets)):
            interpacket_time = (flow_packets[i].time - flow_packets[i - 1].time).total_seconds()
            interpacket_times.append(interpacket_time)

    return interpacket_times

def flow_overhead_ratios(flows):
    # calculate overhead ratio of all flows
    overhead_ratios = []
    for flow_key in flows.keys():
        flow = flows[flow_key]
        hdrs_size = flow.total_hdr_size
        data_size = flow.num_bytes + flow.total_hdr_size
        if flow.num_bytes == 0:
            # if no data transferred, mark as infinity
            data_size = 9999
        overhead_ratios.append(float(hdrs_size) / data_size)
    return overhead_ratios



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
        #  grapher.graph_CDF_alt([all_durations, tcp_durations, udp_durations], ['All', 'TCP', 'UDP'], 'CDF of flow durations', 'duration (seconds)', 'probability')

        # find packet counts of flows
        all_counts = flow_packet_counts(all_flows)
        tcp_counts = flow_packet_counts(tcp_flows)
        udp_counts = flow_packet_counts(udp_flows)

        # graph CDF of packet counts
        #  grapher.graph_CDF_alt([all_counts, tcp_counts, udp_counts], ['All', 'TCP', 'UDP'], 'CDF of flow sizes in packets', 'number of packets in a flow', 'probability')
        all_sizes = flow_byte_sizes(all_flows)
        tcp_sizes = flow_byte_sizes(tcp_flows)
        udp_sizes = flow_byte_sizes(udp_flows)
        #  grapher.graph_CDF_alt([all_sizes, tcp_sizes, udp_sizes], ['All', 'TCP', 'UDP'], 'CDF of flow sizes in bytes', 'number of bytes in a flow', 'probability')

        tcp_overhead_ratios = flow_overhead_ratios(tcp_flows)
        #  grapher.graph_CDF_alt([tcp_overhead_ratios], ['TCP'], 'CDF of overhead ratios', 'overhead ratio', 'probability')

        # find interpacket arrival times
        tcp_interpacket_times = flow_interpacket_arrival_times(tcp_flows)
        udp_interpacket_times = flow_interpacket_arrival_times(udp_flows)
        all_interpacket_times = flow_interpacket_arrival_times(all_flows)
        #  grapher.graph_CDF([all_interpacket_times, tcp_interpacket_times, udp_interpacket_times], ['All', 'TCP', 'UDP'], 'CDF of interpacket arrival times', 'seconds', 'probability', True)
        grapher.graph_CDF_alt([all_interpacket_times, tcp_interpacket_times, udp_interpacket_times], ['All', 'TCP', 'UDP'], 'CDF of interpacket arrival times', 'seconds', 'probability', use_log_scale=True)



if __name__ == '__main__':
    process_flows()
