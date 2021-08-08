#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import time
def create_ack_packet(packet):
    raw_bytes = packet.get_header(RawPacketContents)
    sequence = int.from_bytes(raw_bytes.data[:4], 'big')
    ACK_packet = Ethernet() + IPv4() + UDP()
    ACK_packet[1].protocol = IPProtocol.UDP
    ACK_packet += sequence.to_bytes(4, 'big')
    ACK_packet += sequence.to_bytes(8, 'big')
    return ACK_packet

def switchy_main(net):
    # print("Blastee setup start...")
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    # print("Blastee setup complete!")

    while True:
        gotpkt = True
        try:
            timestamp,dev,pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
            # print("New packet received!")
            # print("==========Packet Content==========")
            # print(pkt)
            # print("==================================")
            # print("")
            ACK = create_ack_packet(pkt)
            net.send_packet(dev, ACK)

        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet from {}".format(dev))
            log_debug("Pkt: {}".format(pkt))

    #print("No more packets...")
    net.shutdown()
