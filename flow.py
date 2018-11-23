class FlowPacketTCP: 
    def __init__(self, src, dst, src_port, dst_port, time, length, seq, ack):
        self.src = src
        self.dst = dst
        self.src_port = src_port
        self.dst_port = dst_port
        self.time = time
        self.length = length
        self.seq = None
        self.ack = None

    def __lt__(self, other):
        if not(instanceof(self, FlowPacketTCP) and instanceof(other, FlowPacketTCP)):
            return False
        return self.seq < other.seq 
        
