from nodes.node_types import BasicNode, MaliciousNode, FirewallNode
from router.router import Router
from security.firewall import Firewall
from security.ids import IDS
import json

def load_firewall_rules(filepath="config/rules.json"):
    with open(filepath, 'r') as file:
        data = json.load(file)
        return data["rules"]

def setup_network():
    firewall_rules = load_firewall_rules()
    firewall = Firewall(rules=firewall_rules)
    ids = IDS(firewall=firewall)


    node1 = BasicNode(ip_address='0x1A', mac_address='N1')
    node2 = MaliciousNode(ip_address='0x2A', mac_address='N2')
    node3 = FirewallNode(ip_address='0x3A', mac_address='N3', firewall=firewall)
    router = Router(interface_configs=[
        {'ip': '0x11', 'mac': 'R1', 'network': '192.168.1.0/24'},
        {'ip': '0x21', 'mac': 'R2', 'network': '192.168.2.0/24'}
    ])

    print("Simulating network traffic...")
    simulate_network_traffic(ids, node1, node2, node3, router)

def simulate_network_traffic(ids, node1, node2, node3, router):
    node1.send_data(data='Hello Node2', dest_mac=node2.mac_address, dest_ip=node2.ip_address)

    node2.spoof_packet(target_ip=node1.ip_address, payload='Spoofed Hello')



if __name__ == '__main__':
    setup_network()