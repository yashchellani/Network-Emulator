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

  node1 = BasicNode(ip_address='\x1A', mac_address='N1')
  node2 = MaliciousNode(ip_address='\x2A', mac_address='N2')
  node3 = FirewallNode(ip_address='\x2B', mac_address='N3', firewall=firewall, ids=ids)
  node4 = BasicNode(ip_address='\x2C', mac_address='N4')
  router = Router(interface_configs=[
    {'ip': '\x11', 'mac': 'R1', 'network': '\x10/4', 'data_link_address': ('localhost', 8122)}, # old network: 192.168.1.0/24
    {'ip': '\x21', 'mac': 'R2', 'network': '\x20/4', 'data_link_address': ('localhost', 8123)} # old network: 192.168.2.0/24
  ])

  nodes = [node1, node2, node3, node4]
  for node in nodes:
      node.connect_to_data_link()
      node.start_receiving()

  # Assuming Router class also has a connect_to_data_link method
  router.connect_to_data_link()
  router.start_receiving()

  sleep(1)
  print("Simulating network traffic...")
  # simulate_network_traffic(ids, node1, node2, node3, node4, router)

  nodes_dict = {
    "N1": node1,
    "N2": node2,
    "N3": node3,
    "N4": node4
  }

  while True:
    sleep(10)
    command = input("What would you like to do? (exit, sniff, ping, kill): ")
    if command == "ping":
      src = input("src(eg:N1): ")
      while src not in nodes_dict:
        src = input("src(eg:N1): ")
      dest = input("dest(eg:N2): ")
      while dest not in nodes_dict:
        dest = input("dest(eg:N2): ")
      count = int(input("count: "))
      
      run = True
      while(run):
        srcNode = nodes_dict[src]
        destNode = nodes_dict[dest]
          
        if src == dest:
          input("src and dest cannot be the same!")
          src = input("src")
          dest = input("dest")
        else: run = False
        
        print(srcNode)
        print(destNode)
        
        data = "PING"
        for c in range(count):
          srcNode.send_ip_packet(data, destNode.ip_address, protocol=0)
        
    if command == "exit":
      cleanup(node1, node2, node3,  node4, router, data_link, data_link_2, data_link_server)
    elif command == "sniff":
      node2.sniffing_enabled = True
      print("Node2 is now sniffing traffic...")
      
    print("Command: ", command)

def simulate_network_traffic(ids, node1, node2, node3, node4, router):
  # Testing sending over IP
  node1.send_ip_packet(data='Hello Node2', dest_ip=node2.ip_address, protocol=3) # placeholder protocol for messaging
  # node2.send_ip_packet(data='Hello Node1', dest_ip=node1.ip_address, protocol=3)
  # # # Testing sending over Ethernet (nodes in the same LAN)
  # node2.send_ethernet_frame(data='MALICIOUS PAYLOAD', dest_mac=node3.mac_address, ethertype=3) # placeholder ethertype for random
  # node3.send_ethernet_frame(data='Hello Node4', dest_mac=node4.mac_address, ethertype=3)
  

def cleanup(node1, node2, node3, node4, router, data_link, data_link_2, data_link_server):
  print("Cleaning up...")
  node1.stop_receiving()
  node2.stop_receiving()
  node3.stop_receiving()
  node4.stop_receiving()
  router.shutdown()
  data_link_server.stop()
  data_link_server.join()
  print("Goodbye!")
  exit()


if __name__ == '__main__':
    setup_network()
