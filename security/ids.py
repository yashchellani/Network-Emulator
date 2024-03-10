class IDS:
  def __init__(self, firewall):
    self.firewall = firewall
    self.threat_signatures = ['malware', 'exploit', 'unauthorized access', 'malicious', 'spoofed']
  
  def parse_ethernet_frame_to_packet(self, ethernet_frame):
    print("\nThis is IDS parsing ethernet frame to packet")
    print(f"Ethernet frame: {ethernet_frame}")
    ethernet_frame = ethernet_frame.decode('utf-8')
    parts = ethernet_frame.split(' ')
    print(f"Parts: {parts}")
    if len(parts) < 4:
        return None
    return {
        'src_mac': parts[0],
        'dest_mac': parts[1],
        'data_length': int(parts[2]),
        'data': " ".join(parts[3:])
    }
  
  def analyze_packet(self, packet):
    """Analyze packets for threat signatures."""
    packet = self.parse_ethernet_frame_to_packet(packet)
    print(f"Analyzing packet: {packet['data']}")
    for signature in self.threat_signatures:
      if signature in packet['data'].lower():
        print(f"Threat detected: {signature}. Source MAC: {packet['src_mac']}")
        self.update_firewall(packet['src_mac'])
        return True
    return False

  def update_firewall(self, mac):
    """Update firewall rules to block traffic from detected threats."""
    print(f"Updating firewall rules to block MAC: {mac}")
    
    new_rule_conditions = {
        "mac": mac,
    }
    self.firewall.add_rule('block', new_rule_conditions)
