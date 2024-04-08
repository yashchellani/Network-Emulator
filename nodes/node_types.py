from .node import Node
import socket
from time import sleep

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

    def arp_spoof(self, dest_ip, fake_ip):
        if not self._ip_in_network(dest_ip):
            print("Can only spoof devices in LAN!")
            return
        
        if dest_ip not in self.arp_table:
            # send ARP query to our data link
            arp_query = f"{self.mac_address} {self.ip_address} 00 {dest_ip} {0} ARP_QUERY"
            self.send_ethernet_frame(arp_query, "FF", 1)

            # wait until a response
            timeout_limit = 5
            timeout_counter = 0
            
            while dest_ip not in self.arp_table:
                if timeout_counter > timeout_limit:
                    print("Timeout while waiting for ARP resolution...")
                    return
                print("Waiting for ARP response...")
                sleep(1) # life would be better with asyncio
                timeout_counter += 1

        dest_mac = self.arp_table[dest_ip]

        arp_response = f"{dest_mac} {dest_ip} {self.mac_address} {fake_ip} {1} ARP_RESPONSE"
        self.send_ethernet_frame(arp_response, dest_mac, 1)

    def disable_sniffing(self):
        self.sniffing_enabled = False

    def sniff_traffic(self, packet):
        print(f"Sniffy sniffy: {packet}")
    
    def ddos_attack(self, dest_ip):
        for _ in range(100):
            self.send_ip_packet("DDOS", dest_ip, 0)
            sleep(0.1)


class FirewallNode(Node):
  def __init__(self, ip_address, mac_address, firewall, ids):
    super().__init__(ip_address, mac_address, firewall, ids)
