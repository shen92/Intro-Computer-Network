#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time

from switchyard.lib.packet.util import *
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net):
        self.net = net
        self.interface_table = self.create_interface_table()
        self.arp_table = self.create_arp_table()  # 1.  Initialize an empty arp_table for storing ARP entries which is mapping of IP addresses to MAC addresses.
        # other initialization stuff here

    def create_interface_table(self):
        interfaces = []
        for interface in self.net.interfaces():
            interfaces.append(interface)
        return interfaces

    def create_arp_table(self):
        arp_table = {}
        return arp_table

    def insert(self, targetprotoaddr, targethwaddr):
        self.arp_table.update({targetprotoaddr: targethwaddr})
        return

    def reply_arp_packet(self, output_port, senderhwaddr, targethwaddr, senderprotoaddr, targetprotoaddr):
        arp_reply_packet = create_ip_arp_reply(senderhwaddr, targethwaddr, targetprotoaddr, senderprotoaddr)
        self.net.send_packet(output_port, arp_reply_packet)
        return

    def router_main(self):
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            gotpkt = True
            try:
                timestamp, dev, pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                print("===============Start Got Packet=================")
                ethernet = pkt.get_header(Ethernet)
                print(pkt)
                print(ethernet.ethertype)
                if ethernet.ethertype == EtherType.ARP:  # 2. Upon receiving a packet, determine whether it is an ARP request.
                    arp = pkt.get_header(Arp)
                    # Source IP address:         senderprotoaddr
                    # Destination IP address:    targetprotoaddr
                    # Source MAC address:        senderhwaddr
                    # Destination MAC address:   targethwaddr
                    print("Source IP address:\t\t", arp.senderprotoaddr)
                    print("Destination IP address:\t\t", arp.targetprotoaddr)
                    print("Source MAC address:\t\t", arp.senderhwaddr)
                    print("Destination MAC address:\t", arp.targethwaddr)
                    for interface in self.interface_table:
                        if arp.targetprotoaddr == interface.ipaddr and arp.operation == ArpOperation.Request:  # If ARP Request
                            print("ARP Request, should REPLY")
                            self.insert(arp.senderprotoaddr, arp.senderhwaddr)
                            self.reply_arp_packet(interface.name, interface.ethaddr, arp.senderhwaddr,
                                                  arp.senderprotoaddr, arp.targetprotoaddr)
                        elif arp.targetprotoaddr == interface.ipaddr and arp.operation == ArpOperation.Reply:  # If ARP Reply
                            print("ARP Reply, should INSERT")
                            self.insert(arp.senderprotoaddr, arp.senderhwaddr)  # Target ip, Target mac
                log_debug("Got a packet: {}".format(str(pkt)))
                print("================End Got Packet==================\n\n")


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
