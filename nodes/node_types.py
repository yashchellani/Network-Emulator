from .node import Node

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

    def spoof_packet(self, target_ip, payload):
        pass

    def sniff_traffic(self, packet):
        pass

class FirewallNode(BasicNode):
  def __init__(self, ip_address, mac_address, firewall):
    super().__init__(ip_address, mac_address)
    self.firewall = firewall

  def receive_data(self, data):
      # Use the firewall to check the incoming data
    packet = self._create_packet(data)
    action = self.firewall.apply_rules(packet)
    if action == 'allow':
        super().receive_data(data)
    else:
        print(f"Packet blocked by firewall at {self.ip_address}")

  def _create_packet(self, data):
    # Create a packet dictionary from the data, this is a placeholder
    # In a real implementation, you would extract packet details such as src_ip, dest_ip, etc.
    return {'data': data}