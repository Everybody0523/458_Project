import scapy.all as scapy
import sys

def process_packet(packet):
    link_name = packet.payload.name
    network_packet = None
    if packet.payload.name == 'Raw':
        network_packet = packet.payload
    else:
        network_packet = packet.payload.payload
    network_name = network_packet.name
    if network_name == 'Raw':
        print packet.show()
    transport_packet = network_packet.payload
    transport_name = transport_packet.name
    if transport_name == 'Raw':
        print packet.show()
    return link_name, network_name, transport_name

def process_packets(infile):
    pkts = scapy.rdpcap(infile)
    protocol_types = {}
    for packet in pkts:
        link_type, network_type, transport_type = process_packet(packet)
        if (link_type, network_type, transport_type) not in protocol_types:
            protocol_types[(link_type, network_type, transport_type)] = 1
        else:
            protocol_types[(link_type, network_type, transport_type)] += 1
    for link_type, network_type, transport_type in sorted(protocol_types.keys()):
        print 'link_type:{0} network_type:{1} transport_type={2}, count={3}'.format(link_type, network_type, transport_type, protocol_types[(link_type, network_type, transport_type)])

if __name__ == '__main__':
    process_packets(sys.argv[1])
