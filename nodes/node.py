import socket

class Node:
    def __init__(self, ip_address, mac_address):
        self.ip_address = ip_address
        self.mac_address = mac_address

    def send_data(self, data, dest_mac, dest_ip):
        """
        Emulates sending data over Ethernet to a specific destination.
        """
        ethernet_frame = self._construct_ethernet_frame(dest_mac, data)
        print(f"Sent data to {dest_mac}: {ethernet_frame}")

    def receive_data(self):
        """
        Emulates receiving data over Ethernet.
        """
        data, addr = self.socket.recvfrom(1024)  # Buffer size of 1024 bytes
        src_mac, dest_mac, data_length, data = self._parse_ethernet_frame(data)
        if dest_mac == self.mac_address:
            print(f"Received data: {data} from {src_mac}")
            self._process_received_data(data, src_mac)
        else:
            print(f"Data not for me. Dropping data from {src_mac}")

    def _construct_ethernet_frame(self, dest_mac, data):
        """
        Constructs an Ethernet frame with source and destination MAC addresses and data.
        """
        data_length = len(data)
        ethernet_frame = f"{self.mac_address} {dest_mac} {data_length} {data}"
        return ethernet_frame.encode('utf-8')

    def _parse_ethernet_frame(self, frame):
        """
        Parses an Ethernet frame into its components.
        """
        frame = frame.decode('utf-8')
        src_mac, dest_mac, data_length, data = frame.split(' ', 3)
        return src_mac, dest_mac, int(data_length), data

    def _process_received_data(self, data, src_mac):
        """
        Placeholder method for processing received data. To be overridden in subclasses.
        """
        print(f"Data from {src_mac}: {data}")

    def connect_to_node(self, node_mac, node_ip):
        """
        Connects to another node by storing its MAC and IP addresses.
        """
        self.connected_nodes[node_mac] = node_ip

    def disconnect_from_node(self, node_mac):
        """
        Disconnects from another node by removing its MAC address.
        """
        if node_mac in self.connected_nodes:
            del self.connected_nodes[node_mac]