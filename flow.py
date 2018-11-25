class FlowPacketTCP: 
    def __init__(self, src, dst, src_port, dst_port, time, length, seq, ack, flags):
        self.src = src
        self.dst = dst
        self.src_port = src_port
        self.dst_port = dst_port
        self.time = time
        self.length = length
        self.seq = seq
        self.ack = ack
        self.flags = flags

    def __lt__(self, other):
        if not(isinstance(self, FlowPacketTCP) and isinstance(other, FlowPacketTCP)):
            return False
        return self.seq < other.seq 
        
