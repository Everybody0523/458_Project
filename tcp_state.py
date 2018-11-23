import dpkt
import sys
import datetime
import socket
from dpkt.compat import compat_ord
import grapher as graphMeDaddy
import find_flow 

def reseted(flow_list):
    for pkt in flow_list:
        if (pkt.flags & dpkt.tcp.TH_RST):
            return True
    return False
    

def finished_nicely(flow_list):
    A_sent_FIN = False
    A_FIN_index = -1
    B_sent_FIN = False
    B_sent_FIN = -1
    A_ack_B = False
    B_ack_A = False
    A = (flow_list[0].src, flow_list[0].src_port)
    B = (flow_list[0].dst, flow_list[0].dst_port)
    i = 0
    for pkt in flow_list:
        if (pkt.flags & dpkt.tcp.TH_FIN) and ((pkt.src, pkt.src_port) == A): 
            A_sent_FIN = True
            A_FIN_index = i
            print "A sent FIN at {0}".format(A_FIN_index)
        if (pkt.flags & dpkt.tcp.TH_FIN) and ((pkt.src, pkt.src_port) == B):
            B_sent_FIN = True
            B_FIN_index = i
            print "B sent FIN at {0}".format(B_FIN_index)
        i += 1

    if A_sent_FIN and B_sent_FIN:
        print A
        print B
        print "-----"
 
    i = 0
    for pkt in flow_list:
        if (pkt.flags & dpkt.tcp.TH_ACK) and ((pkt.src, pkt.src_port) == A) and i > B_sent_FIN:
            A_ack_B = True
        if (pkt.flags & dpkt.tcp.TH_ACK) and ((pkt.src, pkt.src_port) == B) and i > A_sent_FIN:
            B_ack_A = True
        i += 1
    no_reset = not reseted(flow_list)
    return A_sent_FIN and B_sent_FIN and A_ack_B and B_ack_A and no_reset
       

def still_ongoing(flow_list): 
    if finished_nicely(flow_list) or reseted(flow_list):
        return False
    else:
        if (find_flow.last_timestamp - flow_list[-1].time < datetime.timedelta(minutes=5)):
            return True
        else:
            return False


def has_failed(flow_list):
    if finished_nicely(flow_list) or reseted(flow_list):
        return False
    else:
        if (find_flow.last_timestamp - flow_list[-1].time < datetime.timedelta(minutes=5)):
            return False
        else:
            return True 
 

def find_final_state(tcp_dict):
    count_REQUEST = 0
    count_RESET = 0
    count_FINISHED = 0
    count_ONGOING = 0
    count_FAILED = 0
    flows = tcp_dict.values()
    for f in flows:
        print f[-1].flags
        if (f[-1].flags & dpkt.tcp.TH_SYN) and len(f) == 1: 
            count_REQUEST += 1
        if reseted(f):
            count_RESET += 1
        if len(f) > 1: 
            if finished_nicely(f):
                for pkt in f:
                    print format(pkt.flags, '#010b')
                print '------------------------'
                count_FINISHED += 1
        if still_ongoing(f):
            count_ONGOING += 1
        if has_failed(f):
            count_FAILED += 1
    print "Request only: " + str(count_REQUEST)
    print "Connection Reset: {0}".format(count_RESET)
    print "Connection Finished Successfully: {0}".format(count_FINISHED)
    print "Connection Ongoing: {0}".format(count_ONGOING)
    print "Connection Failed: {0}".format(count_FAILED)
    print len(flows)


if __name__ == "__main__":
    pathName = sys.argv[1]
    with open(pathName, 'rb') as meepFile:
        pcap = dpkt.pcap.Reader(meepFile)
        temp_tup = find_flow.find_flows(pcap)
        tcp_dict = temp_tup[4]
        find_final_state(tcp_dict)
    print find_flow.last_timestamp
