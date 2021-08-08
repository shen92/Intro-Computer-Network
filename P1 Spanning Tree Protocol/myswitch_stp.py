from switchyard.lib.userlib import *
from SpanningTreeMessage import *
from time import sleep

def get_stp_packet_to_bytes(root_id, hops, src, dst):
    spanningTreeMessage = SpanningTreeMessage(root_id=root_id, hops_to_root=hops, switch_id=src)
    Ethernet.add_next_header_class(EtherType.SLOW, SpanningTreeMessage)
    stp_packet = Ethernet(src=src, dst=dst, ethertype=EtherType.SLOW) + spanningTreeMessage
    return stp_packet.to_bytes()

def is_stp_packet(packet):
    return "SpanningTreeMessage" in str(packet)

#net:           the net object
#interface:     specific port of switch's ports
#root_id:       argument of SpanningTreeMessage()
#hops_to_root:  argument of SpanningTreeMessage()
#switch_id:     argument of SpanningTreeMessage()
#This method generates a stp packet in bytes and send it to its destination from a specific interface
def send_stp_packet(net, interface, root_id, hops_to_root, switch_id):
    stp_in_bytes = get_stp_packet_to_bytes(root_id, hops_to_root, switch_id, 'ff:ff:ff:ff:ff:ff')
    stp_packet = Packet(stp_in_bytes)
    net.send_packet(interface.name, stp_packet)

#input int timestamp, str input_port, Packet packet
#return dict() packet
def parse_stp_packet(timestamp, incoming_interface, recv_packet):
    packet = dict()
    stp_packet_str = str(recv_packet)
    spanning_tree_message = stp_packet_str[(stp_packet_str.find("SpanningTreeMessage ") + len("SpanningTreeMessage ")):]
    stm = spanning_tree_message.split(', ')
    root = stm[0][stm[0].find('root: ') + len('root: '):]
    hops_to_root = stm[1][stm[1].find('hops-to-root: ') + len('hops-to-root: '):]
    switch_id = stm[2][stm[2].find('switch_id: ')+len('switch_id: '): len(stm[2]) - 1]
    packet["root"] = root
    packet["hops_to_root"] = int(hops_to_root)
    packet["switch_id"] = switch_id
    packet["timestamp"] = timestamp
    packet["incoming_interface"] = incoming_interface
    return packet


class Switch:
    def __init__(self, id, ports):
        self.id = id      #switch id
        self.hops = 0    #hops to the root_switch
        self.root_switch_id = id     #netwrok root_switch switch
        self.port_status = dict()
        for port in ports:
            self.port_status[port] = 0    #0 for forward, 1 for block
        self.last_stp_time = None   #the time at which the last spanning tree message was received
        self.root_interface = None    #the interface on which spanning tree message from the perceived root arrives

    def set_last_stp_time(self, last_stp_time):
        self.last_stp_time = last_stp_time
    
    def get_last_stp_time(self):
        return self.last_stp_time

    def get_root_interface(self):
        return self.get_root_interface

    def needs_flood(self, stp_packet):
        if stp_packet['incoming_interface'] == self.root_interface: #8
            self.hops = stp_packet['hops_to_root'] + 1
            self.root_switch_id = stp_packet['root']
            self.last_stp_time = stp_packet['timestamp']
            self.root_interface = stp_packet['incoming_interface'] 
            stp_packet['switch_id'] = self.id
            stp_packet['hops_to_root'] = self.hops
            return True, stp_packet
        if stp_packet['root'] < self.root_switch_id:  #9
            self.hops = stp_packet['hops_to_root'] + 1
            self.root_switch_id = stp_packet['root']
            self.root_interface = stp_packet['incoming_interface']
            self.last_stp_time = stp_packet['timestamp']
            stp_packet['switch_id'] = self.id
            stp_packet['hops_to_root'] = self.hops
            for keys in self.port_status.keys():
                self.port_status[keys] = 0
            return True, stp_packet
        if stp_packet['root'] > self.root_switch_id: #10
            self.port_status[stp_packet['incoming_interface']] = 0
            return False, None
        if stp_packet['root'] == self.root_switch_id: #11
            if (stp_packet['hops_to_root'] + 1 < self.hops) or (stp_packet['hops_to_root'] + 1 == self.hops and self.root_switch_id > stp_packet['switch_id']):
                self.port_status[stp_packet['incoming_interface']] = 0
                self.port_status[self.root_interface] = 1
                self.root_interface = stp_packet['incoming_interface']
                self.hops = stp_packet['hops_to_root'] + 1
                self.root_switch_id = stp_packet['root']
                self.last_stp_time = stp_packet['timestamp']
                stp_packet['switch_id'] = self.id
                stp_packet['hops_to_root'] = self.hops
                return True, stp_packet
            if stp_packet['hops_to_root'] + 1 > self.hops:
                self.port_status[stp_packet['incoming_interface']] = 1
                return False, None
            else:
                self.port_status[stp_packet['incoming_interface']] = 1
                return False, None

class Node:
    def __init__(self, key, value):
        self.prev = None
        self.next = None
        self.key = key
        self.value = value

class LRUCache:
    def __init__(self):
        self.capacity = 5
        self.head = Node(-1, -1)
        self.tail = Node(-1, -1)
        self.head.next = self.tail
        self.tail.prev = self.head
        self.key_node_dict = dict()
        self.val_key_dict = dict()

    def _updateOrder(self, node):
        node.prev = self.head
        node.next = self.head.next
        node.prev.next = node
        node.next.prev = node

    def _restart(self, node):
        node.prev.next = node.next
        node.next.prev = node.prev

    def get(self, key):
        if key not in self.key_node_dict.keys():
            return None
        node = self.key_node_dict[key]
        self._restart(node)
        self._updateOrder(node)
        return node.value
        
    def add(self, key, value):
        node = None
        if value in self.val_key_dict.keys():
            old_key = self.val_key_dict[value]
            del self.val_key_dict[value]
            node = self.key_node_dict[old_key]
            del self.key_node_dict[old_key]
            self._restart(node)
        self.val_key_dict[value] = key

        if key in self.key_node_dict.keys():
            node = self.key_node_dict[key]
            node.value = value
            self._restart(node)
        else:
            if len(self.key_node_dict) == self.capacity:
                del self.key_node_dict[self.tail.prev.key]
                self._restart(self.tail.prev)    
            node = Node(key, value)
            self.key_node_dict[key] = node
        self._updateOrder(node)

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = set([intf.ethaddr for intf in my_interfaces])
    myports = set([intf.name for intf in my_interfaces])
    lru = LRUCache()

    #Setup current_switch
    id = min(mymacs)
    currentSwitch = Switch(str(id), myports)
    for interface in my_interfaces:
        send_stp_packet(net, interface, currentSwitch.root_switch_id, 0 , currentSwitch.id)

    while True:
        try:
            timestamp, input_port, packet = net.recv_packet()
        except NoPackets:
            if currentSwitch.root_switch_id == currentSwitch.id:
                sleep(2)
                for interface in my_interfaces:
                    send_stp_packet(net, interface, currentSwitch.root_switch_id, currentSwitch.hops, currentSwitch.id)
            continue
        except Shutdown:
            return

        if is_stp_packet(packet): 
            currentSwitch.set_last_stp_time(timestamp)
            #packet_root, packet_hops, packet_switch_id = parse_stp_packet(packet)
            received_packet = parse_stp_packet(timestamp, input_port, packet)
            needs_flood, new_stp_packet = currentSwitch.needs_flood(received_packet)
            if needs_flood:
                for interface in my_interfaces:
                    if interface.name != input_port:
                        send_stp_packet(net, interface, new_stp_packet['root'], new_stp_packet['hops_to_root'], new_stp_packet['switch_id'])

        else:
            if timestamp - currentSwitch.get_last_stp_time() > 10:
                currentSwitch = Switch(str(id), myports)

            lru.add(packet[0].src, input_port)
            #log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))

            if packet[0].dst in mymacs:
                log_debug ("Packet intended for me")
            else:
                output_port = lru.get(packet[0].dst)
                if output_port is not None:
                    net.send_packet(output_port, packet)

                else:
                    for interface in my_interfaces:
                        if interface.name != input_port and currentSwitch.port_status[interface.name] == 0:
                            net.send_packet(interface.name, packet)
    net.shutdown()