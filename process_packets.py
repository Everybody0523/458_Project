import scapy.all as scapy
import sys
import dpkt
import datetime
import socket
from dpkt.compat import compat_ord

def process_packet(packet):
    link_name = packet.name
    network_packet = packet.payload.payload
    network_name = network_packet.name
    if network_name == 'IP':
        network_name += 'v' + str(network_packet.version)
    else:
        # all other network protocols are other
        network_name = 'Other'
    transport_packet = network_packet.payload
    transport_name = transport_packet.name
    if transport_name == 'ICMP':
        # count ICMP as a network packet
        network_name = 'ICMP'
        transport_name = None
    elif transport_name == 'Raw':
        # no transport layer, probably something like ARP
        transport_name = None
    elif transport_name != 'TCP' and transport_name != 'UDP':
        # if not TCP, UDP or ICMP, count as other
        transport_name = 'Other'
    return link_name, network_name, transport_name


def add_protocol_count(protocol_dict, key):
    if key is None:
        return
    if key not in protocol_dict:
        protocol_dict[key] = 1
    else:
        protocol_dict[key] += 1


def print_protocol_count(protocol_dict, number_packets):
    for protocol in sorted(protocol_dict.keys()):
        count = protocol_dict[protocol]
        print '{0} {1} {2}%'.format(protocol, count, (float(count) / number_packets) * 100)


def process_packets(infile):
    pkts = scapy.rdpcap(infile)
    number_packets = len(pkts)
    protocol_types = {}
    link_protocols = {}
    network_protocols = {}
    transport_protocols = {}
    for packet in pkts:
        link_type, network_type, transport_type = process_packet(packet)
        key = link_type, network_type, transport_type
        add_protocol_count(protocol_types, key)
        add_protocol_count(link_protocols, link_type)
        add_protocol_count(network_protocols, network_type)
        add_protocol_count(transport_protocols, transport_type)

    for link_type, network_type, transport_type in sorted(protocol_types.keys()):
        print 'link_type:{0} network_type:{1} transport_type={2}, count={3}'.format(link_type, network_type, transport_type, protocol_types[(link_type, network_type, transport_type)])

    print '\nLink layer:'
    print_protocol_count(link_protocols, number_packets)
    print '\nNetwork layer:'
    print_protocol_count(network_protocols, number_packets)
    print '\nTransport layer:'
    print_protocol_count(transport_protocols, number_packets)


if __name__ == '__main__':
    process_packets(sys.argv[1])


