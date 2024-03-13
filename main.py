from nodes.node_types import BasicNode, MaliciousNode, FirewallNode
from router.router import Router
from security.firewall import Firewall
from security.ids import IDS
from router.data_link import ListenConnections
import socket
import json
from time import sleep

def load_firewall_rules(filepath="config/rules.json"):
  with open(filepath, 'r') as file:
    data = json.load(file)
    return data["rules"]

def setup_network():
  firewall_rules = load_firewall_rules()
  firewall = Firewall(rules=firewall_rules)
  ids = IDS(firewall=firewall)

  # Open socket
  data_link = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  data_link.bind(("localhost", 8122))

  data_link_2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  data_link_2.bind(("localhost", 8123))

  # Open connections to the socket
  data_link.listen(4)
  data_link_2.listen(4)

  data_link_server = ListenConnections(sockets=[data_link, data_link_2])
  data_link_server.start()

  node1 = BasicNode(ip_address='0x1A', mac_address='N1')
  node2 = MaliciousNode(ip_address='0x2A', mac_address='N2')
  node3 = FirewallNode(ip_address='0x3A', mac_address='N3', firewall=firewall, ids=ids)
  node4 = BasicNode(ip_address='0x4A', mac_address='N4')
  router = Router(interface_configs=[
    {'ip': '0x11', 'mac': 'R1', 'network': '192.168.1.0/24'},
    {'ip': '0x21', 'mac': 'R2', 'network': '192.168.2.0/24'}
  ])

  # Connect nodes and router to the data link
  map(lambda node: node.connect_to_data_link(), [node1, node2, node3, node4])
  map(lambda node: node.start_receiving(), [node1, node2, node3, node4])

  # Assuming Router class also has a connect_to_data_link method
  router.connect_to_data_link()

  sleep(1)
  print("Simulating network traffic...")
  simulate_network_traffic(ids, node1, node2, node3, node4, router)

  while True:
    sleep(1)
    command = input("What would you like to do? (exit, sniff, ping, kill): ")
    if command == "exit":
      cleanup(node1, node2, node3, node4, router, data_link, data_link_2, data_link_server)
    print("Command: ", command)

def simulate_network_traffic(ids, node1, node2, node3, node4, router):
  node1.send_data(data='Hello Node2', dest_mac=node2.mac_address, dest_ip=node2.ip_address)
  node2.send_data(data='Hello Node2', dest_mac=node1.mac_address, dest_ip=node1.ip_address)
  node2.send_data(data='MALICIOUS PAYLOAD', dest_mac=node3.mac_address, dest_ip=node3.ip_address)
  node3.send_data(data='Hello Node4', dest_mac=node4.mac_address, dest_ip=node4.ip_address)
  

def cleanup(node1, node2, node3, node4, router, data_link, data_link_2, data_link_server):
  print("Cleaning up...")
  node1.stop_receiving()
  node2.stop_receiving()
  node3.stop_receiving()
  node4.stop_receiving()
  data_link_server.stop()
  data_link_server.join()
  print("Goodbye!")
  exit()


if __name__ == '__main__':
    setup_network()
