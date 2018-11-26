import dpkt
class Flow:
    def __init__(self, src, dst, src_port, dst_port):
        self.src = src
        self.dst = dst
        self.src_port = src_port
        self.dst_port = dst_port
        self.num_packets = 0
        self.num_bytes = 0
        self.first_timestamp = None
        self.last_timestamp = None
        self.type = type
        self.packets = []
        self.total_hdr_size = 0
        self.num_bytes_with_hdrs = 0
    
    def add_packet(self, packet):
        self.packets.append(packet)
        self.num_bytes += packet.data_length
        self.total_hdr_size += packet.link_hdr_length + packet.ip_hdr_length + packet.transport_hdr_length
        self.num_bytes_with_hdrs += packet.total_length
        if not self.first_timestamp:
            self.first_timestamp = packet.time
        if self.last_timestamp and packet.time < self.last_timestamp:
            print 'ERROR: packet timestamp out of order'
            return
        self.last_timestamp = packet.time
        self.num_packets += 1

    def flow_duration(self):
        return (self.last_timestamp - self.first_timestamp).total_seconds()


class FlowPacket:
    def __init__(self, time, total_length, link_hdr_length, ip_hdr_length, transport_hdr_length, rev=False):
        self.time = time
        # total length of the packet, including all headers
        self.total_length = total_length
        self.link_hdr_length = link_hdr_length
        self.ip_hdr_length = ip_hdr_length
        self.transport_hdr_length = transport_hdr_length
        self.data_length = total_length - link_hdr_length - ip_hdr_length - transport_hdr_length
        self.rev = rev 


class FlowPacketTCP(FlowPacket):
    def __init__(self, time, total_length, link_hdr_length, ip_hdr_length, transport_hdr_length, seq, ack, flags):
        FlowPacket.__init__(self, time, total_length, link_hdr_length, ip_hdr_length, transport_hdr_length)
        self.seq = seq
        self.ack = ack
        self.flags = flags

    def __lt__(self, other):
        if not(isinstance(self, FlowPacketTCP) and isinstance(other, FlowPacketTCP)):
            return False
        return self.seq < other.seq 
        
