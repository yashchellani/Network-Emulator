import socket
import threading
from time import sleep
from cachetools import TTLCache

class Node:
    def __init__(self, ip_address, mac_address, firewall=None, ids=None):
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.data_link_address = ('localhost', 8122) if mac_address == 'N1' else ('localhost', 8123)
        self.data_link_socket = None
        self.running = True
        self.receiving_thread = None
        self.firewall = firewall
        self.ids = ids
        # self.ids_lock = threading.Lock()

        # TODO: Come up with a better way of calculating the default gateway (input it when initializing the node?)
        # Cause yes we can derive it from the IP address but right now we're assuming subnet mask is always 4 bits in front

        _mask = int('11110000', 2)
        default_gateway = (ord(ip_address) & _mask) + 1
        # print("Default Gateway: ", bin(default_gateway))
        self.default_gateway = chr(default_gateway)

        self.arp_table = TTLCache(maxsize=100, ttl=60)
        self.connected_nodes = {}


    def connect_to_data_link(self):
        """Establishes a connection to the data link server."""
        self.data_link_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.data_link_socket.connect(self.data_link_address)
        print(f"\n{self.mac_address} connected to data link")

    def send_ip_packet(self, data, dest_ip, protocol, src_ip=None):
        """
        Emulates sending data over IP to a specific destination
        """
        print("\nSending IP packet...")

        # If IP is part of our LAN, send to it directly, otherwise go through the default gateway
        arp_dest = dest_ip if self._ip_in_network(dest_ip) else self.default_gateway

        # If destination not in ARP table, send ARP query
        if arp_dest not in self.arp_table:
            # send ARP query to our data link
            arp_query = f"{self.mac_address} {self.ip_address} 00 {arp_dest} {0} ARP_QUERY"
            self.send_ethernet_frame(arp_query, "FF", 1)

            # wait until a response
            timeout_limit = 5
            timeout_counter = 0
            while arp_dest not in self.arp_table:
                if timeout_counter > timeout_limit:
                    print("Timeout while waiting for ARP resolution...")
                    return
                print("Waiting for ARP response...")
                sleep(1) # life would be better with asyncio
                timeout_counter += 1

        # Find the MAC address
        dest_mac = self.arp_table[arp_dest]
        
        data_length = len(data)

        if src_ip is None:
            src_ip = self.ip_address

        ip_packet = f"{src_ip} {dest_ip} {str(protocol)} {data_length} {data}"

        self.send_ethernet_frame(ip_packet, dest_mac, 0) # encapsulate inside ethernet frame

    def send_ethernet_frame(self, data, dest_mac, ethertype):
        """
        Emulates sending data over Ethernet to a specific destination.
        """
        ethernet_frame = self._construct_ethernet_frame(dest_mac, ethertype, data)
        try:
            self.data_link_socket.send(ethernet_frame)
            print(f"\nSent data to {dest_mac}: {ethernet_frame}")
        except ConnectionAbortedError as e:
            print(f"Failed to send data, connection was aborted: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def start_receiving(self):
        """Start a new thread to listen for incoming messages."""
        self.receiving_thread = threading.Thread(target=self.receive_data)
        self.receiving_thread.start()

    def receive_data(self):
        """Continuously listen for incoming data and print it."""
        try:
            while self.running:
                data, addr = self.data_link_socket.recvfrom(1024)  # Buffer size of 1024 bytes
                if self.ids:
                    print(f"\nAnalyzing packet: {data}")
                    # with self.ids_lock:  # Acquire the lock
                    self.ids.analyze_packet(data)

                src_mac, dest_mac, data_length, ethertype, ethernet_payload = self._parse_ethernet_frame(data)
                # print(f"\nReceived data: {ethernet_payload} for {dest_mac} and I am {self.mac_address}")

                if self.firewall and self.firewall.is_mac_blocked(src_mac):
                    print(f"\nIP address {addr[0]} is blocked. Dropping data from {src_mac} to {dest_mac}")
                    continue

                if dest_mac == self.mac_address:
                    print(f"\nNode {self.mac_address} - Received data: {ethernet_payload} from {src_mac}")
                    self._process_received_data(ethernet_payload, src_mac, ethertype)
                elif dest_mac == "FF":
                    print(f"\nReceived broadcast from {src_mac}")
                    self._process_received_data(ethernet_payload, src_mac, ethertype)
                else:
                    if hasattr(self, 'sniff_traffic') and self.ip_address not in [src_mac, dest_mac]:
                        print(f"Sniffing from {src_mac} to {dest_mac}")
                        if self.sniffing_enabled:
                            self.sniff_traffic(data)
                    else:   
                        print(f"\nData not for me {self.mac_address}. Dropping data from {src_mac} to {dest_mac}.")
        except Exception as e:
            self.running = False

    def stop_receiving(self):
        """Stop listening for incoming data."""
        self.running = False
        sleep(1)
        try:
        # Shutdown the socket connection before closing
            self.data_link_socket.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            print(f"Error shutting down the socket: {e}")
        finally:
            self.data_link_socket.close()
        self.receiving_thread.join()

    def _construct_ethernet_frame(self, dest_mac, ethertype, data):
        """
        Constructs an Ethernet frame with source and destination MAC addresses and data.
        """
        data_length = len(data)
        ethernet_frame = f"{self.mac_address} {dest_mac} {data_length} {ethertype} {data}"
        return ethernet_frame.encode('utf-8')

    def _parse_ethernet_frame(self, frame):
        """
        Parses an Ethernet frame into its components.
        """
        frame = frame.decode('utf-8')
        src_mac, dest_mac, data_length, ethertype, data = frame.split(' ', 4)
        return src_mac, dest_mac, int(data_length), int(ethertype), data
    
    def _parse_arp_packet(self, packet):
        """
        Parses an ARP packet into its components.
        """
        sender_mac, sender_ip, target_mac, target_ip, opcode, message = packet.split(' ', 5)
        return {'sender_mac': sender_mac, 'sender_ip': sender_ip, 'target_mac': target_mac, 'target_ip': target_ip, 'opcode': int(opcode), 'message': message}

    def _process_received_data(self, data, src_mac, ethertype):
        """
        Placeholder method for processing received data. To be overridden in subclasses.
        """
        print("\nProcessing received data...")
        if ethertype == 0: # IP
            # if yes, extract ip header (to get the protocol and source ip)
            src_ip, dst_ip, protocol, data_length, ip_payload = data.split(' ', 4)
            protocol = int(protocol)

            if protocol == 0: # if protocol is ping
                if ip_payload == "PING":
                    # respond to ping
                    t = threading.Thread(target=self.send_ip_packet, args=("PING_RESPONSE", src_ip, 0,), daemon=True)
                    t.start()
            elif protocol == 1: # if protocol is kill
                print("Ded X_X")
                self.stop_receiving()
        elif ethertype == 1: # ARP
            arp_packet = self._parse_arp_packet(data)

            if arp_packet['opcode'] == 0: # if it's an ARP_QUERY
                if arp_packet['target_ip'] == self.ip_address: # if they're querying for our MAC
                    # Send an ARP reply to the querying one
                    arp_response = f"{arp_packet['sender_mac']} {arp_packet['sender_ip']} {self.mac_address} {arp_packet['target_ip']} {1} ARP_RESPONSE"
                    self.send_ethernet_frame(arp_response, arp_packet['sender_mac'], 1)
            elif arp_packet['opcode'] == 1: # if it's an ARP_RESPONSE
                # Update ARP table
                self.arp_table[arp_packet['target_ip']] = arp_packet['target_mac'] # Vulnerability here: we don't check if we sent out an ARP request previously :)
        else:
            print(f"Unknown ethertype: {ethertype}")
            
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

    def _ip_in_network(self, target_ip):
        """
        Checks if an IP address belongs to our LAN
        """
        ip_hex = ord(self.default_gateway)
        target_hex = ord(target_ip)

        if (ip_hex >> 4 & target_hex >> 4) > 0:
            return True
        else:
            return False     
