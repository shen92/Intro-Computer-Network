#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
import random
import time

class PacketCacheEntry(object):
    def __init__(self, pkt, packet_arrival_time, delay):
        self.pkt = pkt
        self.packet_arrival_time = packet_arrival_time
        self.delay = delay

def drop(percent):
    return random.randrange(100) < percent

def delay(mean, std):
    delay =random.gauss(mean, std)
    return delay if delay > 0 else 0

def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    packet_cache = []

    with open("middlebox_params.txt", 'r') as fp:
        params = fp.readline().strip().split(' ')
        random_seed = int(params[1])
        drop_probability = int(params[3])
        mean_delay_of_packets = int(params[5])
        mean_delay_of_packets = mean_delay_of_packets/1000
        standard_deviation_in_delay = int(params[7])/1000
        recv_timeout = int(params[9])
        recv_timeout = recv_timeout/1000

    # Uncomment this line after extracting random seed from params file
    random.seed(random_seed)
    

    while True:
        gotpkt = True
        try:
            timestamp,dev,pkt = net.recv_packet(timeout=recv_timeout)
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet {}".format(pkt))
            if dev == "middlebox-eth1":
                log_debug("Received from blastee")
                # print("Blastee ->ACK Packet-> Blaster")
                # print("==========ACK Packet==========")
                # print(pkt)
                # print("==============================")
                # print()
                '''
                Received ACK
                send directly to blaster. Not dropping ACK packets!
                net.send_packet("middlebox-eth0", pkt)
                '''
                pkt.get_header(Ethernet).src = '40:00:00:00:00:01'
                pkt.get_header(Ethernet).dst = '10:00:00:00:00:01'
                net.send_packet("middlebox-eth0", pkt)
            elif dev == "middlebox-eth0":
                # print("Blaster ->IP Packet-> Blastee")
                # print("==========IP Packet==========")
                # print(pkt)
                # print("==============================")
                drop_packet = drop(drop_probability)
                #print("Drop packet? ->",drop_packet)
                pkt_delay = delay(mean_delay_of_packets, standard_deviation_in_delay)
                log_debug("Received from blaster")
                """
                find if packet needs to dropped
                if not then find the delay and add the packet and other relevant details to a queue
                """
                if not drop_packet:
                    pkt.get_header(Ethernet).src = '40:00:00:00:00:02'
                    pkt.get_header(Ethernet).dst = '20:00:00:00:00:01'
                    # print("Inserting queue")
                    # print("packet delay:", pkt_delay)
                    packet_cache.append(PacketCacheEntry(pkt, timestamp, pkt_delay))
                # print()
            else:
                log_debug("Oops :))")

        """
        process the queue
        """
        current_time = time.time()
        new_packet_cache = []
        # print("==========Packet Cache==========")
        # for packet_cache_entry in packet_cache:
        #     print(packet_cache_entry.pkt)
        # print("================================")
        # print()

        for packet_cache_entry in packet_cache:
            if packet_cache_entry.delay + packet_cache_entry.packet_arrival_time <= current_time:
                net.send_packet("middlebox-eth1", packet_cache_entry.pkt)
                # print("Sent IP packet:")
                # print(packet_cache_entry.pkt)
            else:
                new_packet_cache.append(packet_cache_entry)
            # print()
        packet_cache = new_packet_cache
    # print("No more packets...")
    net.shutdown()
