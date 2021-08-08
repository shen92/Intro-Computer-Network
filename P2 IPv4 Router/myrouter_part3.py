#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time

from switchyard.lib.packet.util import *
from switchyard.lib.userlib import *
from dynamicroutingmessage import DynamicRoutingMessage

class PacketCacheEntry(object):
    def __init__(self, pkt, next_hop_ip, output_port, arp_request):
        self.packet = pkt
        self.next_hop_ip = next_hop_ip
        self.output_port = output_port
        self.arp_request = arp_request
        self.arp_request_count = 1
        self.timestamp = time.time()
        self.flag = 0  # 0 = not sent, 1 = sent, 2 = time out

class Router(object):
    def __init__(self, net):
        print("===============Initialize Router================")
        self.net = net
        self.interface_table = self.create_interface_table()
        self.arp_table = self.create_arp_table()
        self.forwarding_table = self.create_forwarding_table()
        self.dynamic_forwarding_table = self.create_dynamic_forwarding_table()
        self.packet_cache = []

        self.print_arp_table()
        print("Forwarding table:")
        for i in self.forwarding_table:
            print(i)
        print()
        self.print_packet_cache()

        print("=============End Initialize Router==============\n\n")
        # other initialization stuff here
    def create_dynamic_forwarding_table(self):
        return {}

    def create_interface_table(self):
        interfaces = []
        for interface in self.net.interfaces():
            interfaces.append(interface)
        return interfaces

    def interface_table_contains(self, dst):
        for interface in self.interface_table:
            if IPv4Address(interface.ipaddr) == IPv4Address(dst):
                return True
        return False

    def create_arp_table(self):
        arp_table = {}
        return arp_table

    def insert_arp_table(self, targetprotoaddr, targethwaddr):
        self.arp_table.update({targetprotoaddr: targethwaddr})
        self.print_arp_table()
        return

    def create_forwarding_table(self):
        forwarding_table = []
        print("Router Interface Info:")
        for i in self.net.interfaces():
            print(i)
        print("\n")
        for interface in self.net.interfaces():  # Default interface forwarding table
            network_prefix = (int(IPv4Address(interface.netmask)) & int(IPv4Address(interface.ipaddr)))
            forwarding_table.append([IPv4Address(network_prefix), interface.netmask, interface.ipaddr, interface.name])

        with open("forwarding_table.txt", 'r') as file:
            file_content = file.read().strip().split("\n")
            for line in file_content:
                network_prefix, mask, next_hop, output_port = line.strip().split()
                forwarding_table.append(
                    [IPv4Address(network_prefix), IPv4Address(mask), IPv4Address(next_hop), output_port])
        return forwarding_table

    def get_next_hop(self, dest_ip):
        max_prefixlen = 0
        destaddr = IPv4Address(dest_ip)
        goal_next_hop_ip, goal_output_port = None, None

        for key, val in self.dynamic_forwarding_table.items():
            mask, next_hop_addr, next_hop_dev = val
            if (int(key) & int(destaddr)) == int(key):
                prefixlen = IPv4Network(str(key) + '/' + str(mask)).prefixlen
                if prefixlen > max_prefixlen:
                    max_prefixlen = prefixlen
                    goal_next_hop_ip = next_hop_addr
                    goal_output_port = next_hop_dev
        
        if goal_output_port == None and goal_next_hop_ip == None:
            for entry in self.forwarding_table:
                # print(entry)
                # print("dest_ip:\t\t\t", destaddr)
                # print("Current max_prefix_len:\t\t", max_prefixlen)
                # print("Current goal_next_hop_ip:\t", goal_next_hop_ip)
                # print("Current goal_output_port:\t", goal_output_port)
                network_prefix = IPv4Address(entry[0])
                mask = IPv4Address(entry[1])
                matches = (int(mask) & int(destaddr)) == int(network_prefix)
                # print("mask:\t\t", mask, "\tto int:\t", int(mask))
                # print("dest_addr:\t", destaddr, "\tto int:\t", int(destaddr))
                # print("AND result:\t", IPv4Address(int(mask) & int(destaddr)), "\tto int:\t", (int(mask) & int(destaddr)))
                # print("prefix:\t\t", network_prefix, "\tto int:\t", int(network_prefix))
                if matches:
                    prefixlen = IPv4Network(str(network_prefix) + '/' + str(mask)).prefixlen
                    # print("->| Network prefix matches:")
                    # print("->| current prefixlen:\t", prefixlen)
                    if prefixlen > max_prefixlen:
                        max_prefixlen = prefixlen
                        goal_next_hop_ip = IPv4Address(entry[2])
                        goal_output_port = entry[3]
                        # print("---->| Greater prefixlen found:")
                        # print("---->| New max_prefix_len:\t", max_prefixlen)
                        # print("---->| New goal_next_hop_ip:\t", goal_next_hop_ip)
                        # print("---->| New goal_output_port:\t", goal_output_port)
                # print("\n")
        print("goal_next_hop_ip:\t", goal_next_hop_ip)
        print("goal_output_port:\t", goal_output_port, end="\n\n")
        return goal_next_hop_ip, goal_output_port

    def print_packet_cache(self):
        print("Packet Cache:")
        count = 0
        for i in self.packet_cache:
            print('->| Entry #', count)
            print('Packet:\t\t', end="")
            print(i.packet)
            print('Packet dst_ip:\t', end="")
            print(i.next_hop_ip)
            count += 1
        print()
        return

    def print_arp_table(self):
        print("ARP Table:")
        for k in self.arp_table.keys():
            print(k, end="\t")
            print(self.arp_table[k])
        print()
        return

    def insert_packet_cache(self, entry):
        self.packet_cache.append(entry)
        print("Packet has been added to packet cache\n")
        self.print_packet_cache()
        return

    def new_arp_request(self, senderhwaddr, senderprotoaddr, targetprotoaddr):
        ether_header = Ethernet()
        ether_header.ethertype = EtherType.ARP
        ether_header.src = senderhwaddr
        ether_header.dst = 'ff:ff:ff:ff:ff:ff'
        arp_header = Arp(operation=ArpOperation.Request, senderhwaddr=senderhwaddr, senderprotoaddr=senderprotoaddr,
                         targethwaddr='ff:ff:ff:ff:ff:ff', targetprotoaddr=targetprotoaddr)
        return ether_header + arp_header

    def reply_arp_packet(self, output_port, senderhwaddr, targethwaddr, senderprotoaddr, targetprotoaddr):
        arp_reply_packet = create_ip_arp_reply(senderhwaddr, targethwaddr, targetprotoaddr, senderprotoaddr)
        self.net.send_packet(output_port, arp_reply_packet)
        return

    def update_dynamic_forwarding_table(self, dev, prefix, mask, next_hop):
        self.dynamic_forwarding_table[prefix] = (mask, next_hop, dev)
    
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
                print("Input port:\t\t\t", dev)
                print("Packet type:\t\t\t", ethernet.ethertype)
                if ethernet.ethertype == EtherType.ARP:
                    arp_header = pkt.get_header(Arp)
                    # Source IP address:         senderprotoaddr
                    # Destination IP address:    targetprotoaddr
                    # Source MAC address:        senderhwaddr
                    # Destination MAC address:   targethwaddr
                    print("Source IP address:\t\t", arp_header.senderprotoaddr)
                    print("Destination IP address:\t\t", arp_header.targetprotoaddr)
                    print("Source MAC address:\t\t", arp_header.senderhwaddr)
                    print("Destination MAC address:\t", arp_header.targethwaddr)
                    print('\n')
                    for interface in self.interface_table:
                        if arp_header.targetprotoaddr == interface.ipaddr and arp_header.operation == ArpOperation.Request:  # If ARP Request
                            print("ARP Request, should REPLY\n")
                            self.insert_arp_table(arp_header.senderprotoaddr, arp_header.senderhwaddr)
                            self.reply_arp_packet(interface.name, interface.ethaddr, arp_header.senderhwaddr,
                                                  arp_header.senderprotoaddr, arp_header.targetprotoaddr)
                        elif arp_header.targetprotoaddr == interface.ipaddr and arp_header.operation == ArpOperation.Reply:  # If ARP Reply
                            print("ARP Reply, should INSERT\n")
                            self.insert_arp_table(arp_header.senderprotoaddr,
                                                  arp_header.senderhwaddr)  # Target ip, Target mac
                elif ethernet.ethertype == EtherType.IP:
                    ipv4_header = pkt.get_header(IPv4)
                    # Source IP address:        src
                    # Destination IP address:   dst
                    # TTL:                      ttl
                    print("Source IP address:\t\t", ipv4_header.src)
                    print("Destination IP address:\t\t", ipv4_header.dst)
                    print("TTL:\t\t\t\t", ipv4_header.ttl)
                    print('\n')
                    print("CURRENT Forwarding table:")
                    for i in self.forwarding_table:
                        print(i)
                    print()
                    next_hop_ip, output_port = self.get_next_hop(ipv4_header.dst)

                    if not self.interface_table_contains(ipv4_header.dst) and (next_hop_ip is not None) and (
                            output_port is not None):
                        # Get next_hop ip
                        if self.interface_table_contains(next_hop_ip):
                            print("Router has interface to destination IPv4.dst IP's network (prefix)\n")
                            next_hop_ip = ipv4_header.dst
                        else:
                            print("Should send to another network\n")

                        # Get next_hop_mac
                        if next_hop_ip in self.arp_table.keys():
                            print(
                                "Destination MAC-IP mapping exists ARP table (known next_hop_mac), can send IPv4 packet directly.\n")
                            ethernet_header = pkt.get_header(Ethernet)
                            ethernet_header.dst = self.arp_table[next_hop_ip]
                            packet_payload = pkt[IPv4]
                            packet_payload.ttl -= 1
                            self.net.send_packet(output_port, pkt)
                        else:
                            print(
                                "Destination MAC-IP mapping not exists ARP table (unknown next_hop_mac), should send ARP request at",
                                output_port, end="\n\n")
                            output_interface = self.net.interface_by_name(output_port)
                            new_arp_request = self.new_arp_request(output_interface.ethaddr, output_interface.ipaddr,
                                                                   next_hop_ip)
                            self.net.send_packet(output_port, new_arp_request)  # send arp req the first time
                            packet_cache_entry = PacketCacheEntry(pkt, next_hop_ip, output_port, new_arp_request)
                            print(packet_cache_entry.packet)
                            self.insert_packet_cache(packet_cache_entry)
                elif ethernet.ethertype == EtherType.SLOW:
                    dynamic_routing_message = pkt.get_header(DynamicRoutingMessage)
                    prefix = dynamic_routing_message.advertised_prefix
                    next_hop = dynamic_routing_message.next_hop
                    mask = dynamic_routing_message.advertised_mask

                    if 5 <= len(self.dynamic_forwarding_table):
                        self.dynamic_forwarding_table.pop(list(self.dynamic_forwarding_table.keys())[0])
                    self.update_dynamic_forwarding_table(dev, prefix, mask, next_hop)                 

                print("-----Start scan the Packet Cache-----")
                self.print_arp_table()
                for packet_cache_entry in self.packet_cache:
                    print('Packet:\t\t', end="")
                    print(packet_cache_entry.packet)
                    print('Packet dst_ip:\t', end="")
                    print(packet_cache_entry.next_hop_ip)
                    if packet_cache_entry.next_hop_ip in self.arp_table.keys():
                        print("ARP mapping found, can send packet now.")
                        ethernet_header = packet_cache_entry.packet.get_header(Ethernet)
                        ethernet_header.dst = self.arp_table[next_hop_ip]
                        ethernet_header.src = self.net.interface_by_name(output_port).ethaddr
                        packet_payload = packet_cache_entry.packet[IPv4]
                        packet_payload.ttl -= 1
                        print(packet_cache_entry.packet)
                        self.net.send_packet(packet_cache_entry.output_port, packet_cache_entry.packet)
                        packet_cache_entry.flag = 1
                    else:
                        print("ARP mapping not found, should ")
                        new_timestamp = time.time()
                        print("current time:\t", new_timestamp)
                        print("received time:\t", packet_cache_entry.timestamp)
                        print("delta time:\t", new_timestamp - packet_cache_entry.timestamp)
                        if new_timestamp - packet_cache_entry.timestamp > 1:
                            if packet_cache_entry.arp_request_count < 3:
                                packet_cache_entry.timestamp = new_timestamp
                                self.net.send_packet(packet_cache_entry.output_port, packet_cache_entry.arp_request)
                                packet_cache_entry.arpreq_sent_count += 1
                            else:
                                packet_cache_entry.flag = 2

                new_packet_cache = []
                for packet_cache_entry in self.packet_cache:
                    if packet_cache_entry.flag == 0:
                        new_packet_cache.append(packet_cache_entry)

                self.packet_cache = new_packet_cache
                print("-------End scan the Packet Cache------")
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