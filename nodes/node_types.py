from .node import Node
import socket

class BasicNode(Node):
    """
    A basic network node type that can send and receive messages but has no special behaviors.
    """
    def __init__(self, ip_address, mac_address):
        super().__init__(ip_address, mac_address)

    def receive_packet(self, packet):
        print(f"Received packet: {packet}")
    

class MaliciousNode(Node):
    """
    A malicious node capable of conducting network attacks, such as IP spoofing or sniffing.
    """
    def __init__(self, ip_address, mac_address):
        super().__init__(ip_address, mac_address)
        self.sniffing_enabled = True

    def spoof_packet(self, dest_ip, fake_ip):
        self.send_ip_packet("PING", dest_ip, 0, fake_ip)

    def disable_sniffing(self):
        self.sniffing_enabled = False

    def sniff_traffic(self, packet):
        print(f"Sniffy sniffy: {packet}")
        


class FirewallNode(Node):
  def __init__(self, ip_address, mac_address, firewall, ids):
    super().__init__(ip_address, mac_address, firewall, ids)

  def _create_packet(self, data):
    # Create a packet dictionary from the data, this is a placeholder
    # In a real implementation, you would extract packet details such as src_ip, dest_ip, etc.
    return {'data': data}