class IDS:
  def __init__(self, firewall):
    self.firewall = firewall
    self.threat_signatures = ['malware', 'exploit', 'unauthorized access']
  
  def parse_ethernet_frame_to_packet(self, ethernet_frame):
    parts = ethernet_frame.split(' ')
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
    for signature in self.threat_signatures:
      if signature in packet['data']:
        print(f"Threat detected: {signature}. Source IP: {packet['src_ip']}")
        self.update_firewall(packet['src_ip'])
        return True
    return False

  def update_firewall(self, src_ip):
    """Update firewall rules to block traffic from detected threats."""
    print(f"Updating firewall rules to block IP: {src_ip}")
    new_rule_conditions = {'src_ip': src_ip}
    self.firewall.add_rule('block', new_rule_conditions)
