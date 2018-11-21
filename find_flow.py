import dpkt
import sys
import datetime
import socket
from dpkt.compat import compat_ord


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
            elif isinstance(ip.data, dpkt.udp.UDP):
                # UDP packet
                udp = ip.data
                src_port = udp.sport
                dst_port = udp.dport
                add_flow_packet(udp_flows, src, dst, src_port, dst_port, time)

    for flow in tcp_flows.keys():
        src, dst, src_port, src_dst = flow
        num_pkts, start_time, end_time = tcp_flows[flow]
        duration = end_time - start_time
        print '{0}:{2}->{1}:{3} num_pkts={4} duration={5}'.format(src, dst, src_port, src_dst, num_pkts, duration)


def test():
    """Open up a test pcap file and print out the packets"""
    with open(sys.argv[1], 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        find_flows(pcap)


if __name__ == '__main__':
    test()
