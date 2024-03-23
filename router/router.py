import socket
import threading
from time import sleep

network_definitions = {
   '\x10/4': 8122,
   '\x20/4': 8123
}

class Router:
  def __init__(self, interface_configs):
    """
    Initializes the router with configurations for its interfaces.
    Each interface configuration includes its own IP, MAC address, and connected network.
    """
    self.interfaces = interface_configs
    self.data_link_sockets = {} # key: interface MAC, value: associated socket
    self.receiving_threads = {} # key: interface MAC, value: receiving thread
    self.arp_table = {
      # "\x1A": "N1",
      # "\x2A": "N2",
      # "\x2B": "N3"
    } # TODO: un-hardcode
    self.arp_table_lock = threading.Lock()
    self.running = True
  
  def connect_to_data_link(self):
    """Establishes a connection to the data link server."""
    # DATA_LINK_ADDRESS = ("localhost", 8122)
    for interface in self.interfaces:
        ip = interface['ip']
        mac = interface['mac']
        data_link_address = interface['data_link_address']
        self.data_link_sockets[mac] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.data_link_sockets[mac].connect(data_link_address)
        print(f"\nInterface {ip}, MAC {mac} connected to data link at {data_link_address}")

  def start_receiving(self):
        """Start a new thread to listen for incoming messages."""
        for interface in self.interfaces:
          self.data_link_sockets[interface['mac']].settimeout(5.0)  # Set the timeout for blocking socket operations
          self.receiving_threads[interface['mac']] = threading.Thread(target=self.receive_data, args=(interface,))
          self.receiving_threads[interface['mac']].start()

  def receive_data(self, interface):
      """Continuously listen for incoming data and print it."""
      self.data_link_sockets[interface['mac']].settimeout(5.0)  # Setting the timeout here as an example
      try:
          while self.running:
              try:
                  data, addr = self.data_link_sockets[interface['mac']].recvfrom(1024)  # Buffer size of 1024 bytes

                  src_mac, dest_mac, data_length, ethertype, ethernet_payload = self._parse_ethernet_frame(data)
                  print(f"\nReceived data: {ethernet_payload} for {dest_mac} and I am {interface['mac']}")

                  if dest_mac == interface['mac']:
                      print(f"\nRouter Interface {interface['mac']} - Received data: {ethernet_payload} from {src_mac}")
                      self._process_received_data(interface, ethernet_payload, src_mac, ethertype)
                  elif dest_mac == "FF":
                     print(f"\nReceived broadcast from {src_mac}")
                     self._process_received_data(interface, ethernet_payload, src_mac, ethertype)
                  else:
                      print(f"\nData not for me {interface['mac']}. Dropping data from {src_mac} to {dest_mac}.")
              
              except socket.timeout:
                  break
      except Exception as e:
          print("Router exception: ", e)
          self.running = False

  def _process_received_data(self, interface, data, src_mac, ethertype):
    """
    Process received data 
    """
    if ethertype == 0: # IP
      # if yes, extract ip header (to get the protocol and source ip)
      ip_packet = self._parse_ip_packet(data)

      if interface['ip'] == ip_packet['dest_ip']: # if the packet is actually meant for the router
         pass # do something -- can router respond to ping?
      
      else: # if not meant for router
        # route packet to corresponding node
        self.route_packet(ip_packet)
      
    elif ethertype == 1: # ARP
      arp_packet = self._parse_arp_packet(data)
  
      if arp_packet['opcode'] == 0: # if it's an ARP_QUERY
        if arp_packet['target_ip'] == interface['ip']: # if they're querying for our MAC
           # Send an ARP reply to the querying one
           arp_response = f"{arp_packet['sender_mac']} {arp_packet['sender_ip']} {arp_packet['target_ip']} {interface['mac']} {1} ARP_RESPONSE"
           ethernet_frame = self._construct_ethernet_frame(interface['mac'], "FF", 1, arp_response)
           self._send_frame(ethernet_frame, interface)
      elif arp_packet['opcode'] == 1: # if it's an ARP_RESPONSE
         with self.arp_table_lock:
          # Update ARP table
          self.arp_table[arp_packet['target_ip']] = arp_packet['target_mac'] # Vulnerability here: we don't check if we sent out an ARP request previously :)

    print(f"Data from {src_mac}: {data}")

  def route_packet(self, ip_packet):
    """
    Routes an incoming IP packet to the correct interface based on the destination IP.
    """
    # Determine the outgoing interface based on the destination IP
    outgoing_interface = self._find_outgoing_interface(ip_packet['dest_ip'])
    
    if outgoing_interface:
        if ip_packet['dest_ip'] not in self.arp_table:
          # send ARP query out of the outgoing interface
          arp_query = f"{outgoing_interface['mac']} {outgoing_interface['ip']} {ip_packet['dest_ip']} \xFF {0} ARP_QUERY"
          ethernet_frame = self._construct_ethernet_frame(outgoing_interface['mac'], "FF", 1, arp_query)
          self._send_frame(ethernet_frame, outgoing_interface)

        # wait until a response
        while ip_packet['dest_ip'] not in self.arp_table:
            sleep(1) # life would be better with asyncio

        # Find the new MAC address on the ARP table
        new_dest_mac = self.arp_table[ip_packet['dest_ip']]

        # Construct new Ethernet frame with the router's outgoing interface MAC and forward it
        new_frame = self._construct_ethernet_frame(outgoing_interface['mac'], new_dest_mac, 0, ip_packet['data'])
        self._send_frame(new_frame, outgoing_interface)
    else:
        print("No route to host for IP:", ip_packet['dest_ip'])

  def _find_outgoing_interface(self, dest_ip):
    """
    Finds the appropriate outgoing interface for a given destination IP address.
    """
    for interface in self.interfaces:
        if self._ip_in_network(dest_ip, interface['network']):
            return interface
    return None

  def _send_frame(self, ethernet_frame, interface):
    """
    Sends an Ethernet frame out of a specified interface.
    """
    self.data_link_sockets[interface['mac']].send(ethernet_frame)
    print(f"Sending frame out of interface {interface['mac']}: {ethernet_frame}")

  @staticmethod
  def _parse_ethernet_frame(frame):
    """
    Parses an Ethernet frame into its components.
    """
    frame = frame.decode('utf-8')
    src_mac, dest_mac, data_length, ethertype, data = frame.split(' ', 4)
    return src_mac, dest_mac, int(data_length), int(ethertype), data

  @staticmethod
  def _parse_ip_packet(packet):
    """
    Parses an IP packet into its components.
    """
    src_ip, dest_ip, protocol, data_length, data = packet.split(' ', 4)
    return {'src_ip': src_ip, 'dest_ip': dest_ip, 'protocol': int(protocol), 'data_length': int(data_length), 'data': data}
  
  def _parse_arp_packet(self, packet):
    """
    Parses an ARP packet into its components.
    """
    sender_mac, sender_ip, target_ip, target_mac, opcode, message = packet.split(' ', 5)
    return {'sender_mac': sender_mac, 'sender_ip': sender_ip, 'target_ip': target_ip, 'target_mac': target_mac, 'opcode': int(opcode), 'message': message}

  @staticmethod
  def _construct_ethernet_frame(src_mac, dest_mac, ethertype, data):
    """
    Constructs an Ethernet frame with source and destination MAC addresses and data.
    """
    data_length = len(data)
    ethernet_frame = f"{src_mac} {dest_mac} {data_length} {ethertype} {data}"
    return ethernet_frame.encode('utf-8')   

  @staticmethod
  def _ip_in_network(ip, network):
    """
    Checks if an IP address belongs to a network.
    """
    ip_hex = ord(ip)
    network_hex = ord(network[0])

    if ip_hex & network_hex > 0:
       return True
    else:
       return False     
     
  def shutdown(self):
    self.running = False
    sleep(1)
    print("Shutting down router...")
    for mac in self.data_link_sockets:
      try:
        # Shutdown the socket connection before closing
        self.data_link_sockets[mac].shutdown(socket.SHUT_RDWR)
      except Exception as e:
          print(f"Error shutting down the socket: {e}")
      finally:
          self.data_link_sockets[mac].close()
          self.receiving_threads[mac].join()

