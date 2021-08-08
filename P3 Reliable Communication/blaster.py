#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from random import randint
from queue import Queue
import time

def print_output(total_time, num_ret, num_tos, throughput, goodput, estRTT, t_out, min_rtt, max_rtt):
    print("Total TX time (s): " + str(total_time))
    print("Number of reTX: " + str(num_ret))
    print("Number of coarse TOs: " + str(num_tos))
    print("Throughput (Bps): " + str(throughput))
    print("Goodput (Bps): " + str(goodput))
    print("Final estRTT(ms): " + str(estRTT))
    print("Final TO(ms): " + str(t_out))
    print("Min RTT(ms):" + str(min_rtt))
    print("Max RTT(ms):" + str(max_rtt))

def parse_ack_bytes(data):
    sequence_number = int.from_bytes(data[0:4], byteorder='big')
    payload = data[4:].decode('utf-8', 'ignore')
    return sequence_number, payload

def create_data_packet(seq_num, payload):
    sequence_bytes = seq_num.to_bytes(4, byteorder='big')
    payload_bytes = payload.encode('utf-8', 'ignore')
    length_bytes = len(payload_bytes).to_bytes(2, byteorder='big')
    return sequence_bytes + length_bytes + payload_bytes

def switchy_main(net):
    # print("Blaster setup start..")
    set_up_time = time.time()
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    with open("blaster_params.txt", 'r') as fp:
        params = fp.readline().strip().split(' ')
        blastee_ip = str(params[1])
        num = int(params[3])
        # print("Packts:", num)
        length = int(params[5])
        sender_window = int(params[7])
        #print("Sender_window size:", sender_window)
        rtt = int(params[9])/1000
        recv_timeout = int(params[11])
        recv_timeout = recv_timeout/1000
        ewma_parameter = float(params[13])

    LHS = 1
    RHS = 1
    num_reTx, num_coarse_timeout = 0, 0
    size_Tx, size_good_Tx = 0, 0
    estRTT = rtt
    t_out = 2 * estRTT
    min_rtt, max_rtt = -1, -1
    retransmit_queue = Queue()
    pending_pkts_map = {}  # store index of the pending pkts
    send_time_map = {}
    lhs_stuck_time = time.time()
    #print("Blaster setup complete!")

    while LHS <= num:
        # print("(Start)LHS:", LHS)
        gotpkt = True
        sentpkt = False
        try:
            #Timeout value will be parameterized!
            # print("break print 1")
            timestamp,dev,pkt = net.recv_packet(timeout=recv_timeout)
            # print("break print 1")
        except NoPackets:
            log_debug("No packets available in recv_packet")
            # print("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            # print("Got shutdown signal")
            break
        #print("break print 2")
        if gotpkt:
            log_debug("I got a packet")
            # print("I got a ack packet")
            # Verify ACK packet
            if pkt.num_headers() < 4 or type(pkt[1]) is not IPv4 or type(pkt[2]) is not UDP or type(pkt[3]) is not RawPacketContents:
                continue
            seq_num, payload = parse_ack_bytes(pkt[3].to_bytes())
            # print("ACK sequence:", seq_num)
            # print("---------------pending_pkts_map---------------")
            # for pending_pkts_map_entry in pending_pkts_map:
            #     print(pending_pkts_map_entry)
            # print("----------------------------------------------")
            if seq_num in pending_pkts_map:
                # delete pkt from pending map
                del pending_pkts_map[seq_num]
            lhs_copy = LHS
            if len(pending_pkts_map) > 0:
                LHS = min(pending_pkts_map.keys())
            else:
                LHS = RHS
            if lhs_copy < LHS:
                lhs_stuck_time = time.time()
            cur_rtt = timestamp - send_time_map[seq_num]
            estRTT = (1-ewma_parameter)*estRTT + ewma_parameter*(cur_rtt)
            if min_rtt < 0:
                min_rtt = cur_rtt
            else:
                min_rtt = min(min_rtt, cur_rtt)
            if max_rtt < 0:
                max_rtt = cur_rtt
            else:
                max_rtt = max(max_rtt, cur_rtt)

        else:
            log_debug("Didn't receive anything")
            #print("Didn't receive anything")
            current_time = time.time()

            # resend pkt
            # print("lhs_stuck_time:",lhs_stuck_time)
            # print("estRTT:",estRTT)
            # print("current_time:",current_time)
            # print("lhs_stuck_time + estRTT:", lhs_stuck_time + estRTT)
            if lhs_stuck_time + estRTT < current_time:
               
                num_coarse_timeout = num_coarse_timeout + 1
                lhs_stuck_time = current_time
                # enqueue all pending packets
                retransmit_queue.put(LHS)

            seqnum = -1
            while retransmit_queue.qsize() > 0 and seqnum not in pending_pkts_map:
                seqnum = retransmit_queue.get()

            if seqnum in pending_pkts_map:
                retx_pkt = pending_pkts_map[seqnum]
                size_Tx += len(retx_pkt[3].to_bytes())
                num_reTx += 1
                net.send_packet("blaster-eth0", retx_pkt)
                sentpkt = True

            # send new pkt
            if not sentpkt and RHS <= num and RHS - LHS < sender_window:
                '''
                Creating the headers for the packet
                '''
                # print("send new packet")
                # print("RHS:",RHS)
                # print("LHS:",LHS)
                # print("Sender_window:",sender_window)
                eth_hdr = Ethernet(src=mymacs[0], dst='40:00:00:00:00:01', ethertype=EtherType.IP)
                udp_hdr = UDP(src=8080, dst=80)
                ip_hdr = IPv4(src=myips[0], dst=blastee_ip, protocol=IPProtocol.UDP, ttl=64)
                contents_hdr = RawPacketContents(create_data_packet(RHS, 'a' * length))
                size_Tx += len(contents_hdr.to_bytes())
                size_good_Tx += len(contents_hdr.to_bytes())
                pkt = eth_hdr + ip_hdr + udp_hdr + contents_hdr
                send_time_map[RHS] = time.time()
                '''
                Do other things here and send packet
                '''
                pending_pkts_map[RHS] = pkt
                RHS = RHS + 1
                # print("sent packet")
                # print(pkt)
                net.send_packet("blaster-eth0", pkt)
    total_time = time.time() - set_up_time
    print_output(total_time, num_reTx, num_coarse_timeout, size_Tx / total_time, size_good_Tx / total_time, 1000 * estRTT, 1000 * t_out, 1000 * min_rtt, 1000 * max_rtt) 
    net.shutdown()
