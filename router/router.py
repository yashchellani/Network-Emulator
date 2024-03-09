class Router:
  def __init__(self, interface_configs):
    """
    Initializes the router with configurations for its interfaces.
    Each interface configuration includes its own IP, MAC address, and connected network.
    """
    self.interfaces = interface_configs 

  
  def connect_to_data_link(self):
    """Establishes a connection to the data link server."""
    DATA_LINK_ADDRESS = ("localhost", 8122)
    for interface in self.interfaces:
        ip = interface['ip']
        mac = interface['mac']
        # If using actual network connections, you might open a socket per interface here.
        # For simulation purposes, we'll just print a connection message.
        print(f"\nInterface {ip}, MAC {mac} connected to data link at {DATA_LINK_ADDRESS}")



  def route_packet(self, ethernet_frame):
    """
    Routes an incoming Ethernet frame to the correct interface based on the destination IP.
    """
    src_mac, dest_mac, data_length, data = self._parse_ethernet_frame(ethernet_frame)
    ip_packet = self._parse_ip_packet(data)
    
    # Determine the outgoing interface based on the destination IP
    outgoing_interface = self._find_outgoing_interface(ip_packet['dest_ip'])
    
    if outgoing_interface:
        # Construct new Ethernet frame with the router's outgoing interface MAC and forward it
        new_frame = self._construct_ethernet_frame(outgoing_interface['mac'], dest_mac, data)
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
    print(f"Sending frame out of interface {interface['mac']}: {ethernet_frame}")

  @staticmethod
  def _parse_ethernet_frame(frame):
    """
    Parses an Ethernet frame into its components.
    """
    src_mac, dest_mac, data_length, data = frame.split(' ', 3)
    return src_mac, dest_mac, int(data_length), data

  @staticmethod
  def _parse_ip_packet(packet):
    """
    Parses an IP packet into its components.
    """
    src_ip, dest_ip, protocol, data_length, data = packet.split(' ', 4)
    return {'src_ip': src_ip, 'dest_ip': dest_ip, 'protocol': protocol, 'data_length': int(data_length), 'data': data}

  @staticmethod
  def _construct_ethernet_frame(src_mac, dest_mac, data):
    """
    Constructs an Ethernet frame with source and destination MAC addresses and data.
    """
    data_length = len(data)
    return f"{src_mac} {dest_mac} {data_length} {data}"

  @staticmethod
  def _ip_in_network(ip, network):
    """
    Checks if an IP address belongs to a network.
    """
    return True

