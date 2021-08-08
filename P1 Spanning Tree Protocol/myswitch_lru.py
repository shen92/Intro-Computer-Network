from switchyard.lib.userlib import *

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

    lru = LRUCache()

    while True:
        try:
            timestamp, input_port, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        lru.add(packet[0].src, input_port)
        
        # check if the destination exists in the lru.
        # if it doesn't flood 
        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
            output_port = lru.get(packet[0].dst)
            if output_port is not None:
                net.send_packet(output_port, packet)
            else:
                for intf in my_interfaces: #flooding
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()