from nodes.node_types import BasicNode, MaliciousNode, FirewallNode
import json
import socket
from security.firewall import Firewall
from security.ids import IDS
from time import sleep

def load_firewall_rules(filepath="config/rules.json"):
  with open(filepath, 'r') as file:
    data = json.load(file)
    return data["rules"]

def record_node_running(node_type, running):
   "Helper method to ensure that one node type can only be run once"
   existing_nodes = ""
   with open("active_nodes.txt", "r+") as file:
      if running:
         if node_type in existing_nodes:
            raise RuntimeError("Node is already running")
         existing_nodes += node_type + "\n"
      else:
         existing_nodes = existing_nodes.replace(node_type + "\n", "")
      file.seek(0)
      file.write(existing_nodes) 
      file.truncate()
def clean_running_nodes_file():
   with open("active_nodes.txt", "w") as file:
      file.write("")


firewall_rules = load_firewall_rules()
firewall = Firewall(rules=firewall_rules)
ids = IDS(firewall=firewall)

node_configurations = {
    "node1": BasicNode(ip_address='\x1A', mac_address='N1'),
    "node2": MaliciousNode(ip_address='\x2A', mac_address='N2'),
    "node3": FirewallNode(ip_address='\x2B', mac_address='N3', firewall=firewall, ids=ids),
    "node4": BasicNode(ip_address='\x2C', mac_address='N4')
}

if __name__ == '__main__':
    clean_running_nodes_file()
    while True:
      node_type = input("Which type of node do you want to create? (node1, node2, node3, node4) :")
      if node_type not in node_configurations.keys():
         print("Invalid node type")
      else:
         try:
            record_node_running(node_type, True)
            break
         except Exception as e:
            print(e)
         
    node = node_configurations[node_type]
    node.connect_to_data_link()
    node.start_receiving()
  
    while(node.running):
        command = input("What would you like to do? (ping, kill, ddos, ip_spoof, arp_spoof, exit): ")
        if node.running is False:
           print("Node has stopped running")
           exit()
           
        if command == "ping":
            dest = input("Destination node: ")
            dest_node = node_configurations[dest]
            count = int(input("Count: "))

            for c in range(count):
                node.send_ip_packet("PING", dest_node.ip_address, protocol=0)
                sleep(1)

            sleep(10)
        elif command == "kill":
           dest = input("Destination node: ")
           dest_node = node_configurations[dest]

           node.send_ip_packet("KILL", dest_node.ip_address, protocol=1)

           sleep(10)

        elif command == "ip_spoof":
           if not isinstance(node, MaliciousNode):
              print("You are a benign node, unable to spoof!")
           else:
              dest = input("Destination node: ")
              fake_source = input("Spoofed source node: ")

              dest_node = node_configurations[dest]
              fake_node = node_configurations[fake_source]

              node.spoof_packet(dest_node.ip_address, fake_node.ip_address)
        
        elif command == "arp_spoof":
           if not isinstance(node, MaliciousNode):
              print("You are a benign node, unable to spoof!")
           else:
              dest = input("Destination node: ")
              fake_source = input("Spoofed source (nodex or router): ")

              dest_node = node_configurations[dest]
              fake_ip = node.default_gateway if fake_source == "router" else node_configurations[fake_source].ip_address

              node.arp_spoof(dest_node.ip_address, fake_ip)
        elif command == "ddos":
             if not isinstance(node, MaliciousNode):
               print("You are a benign node, unable to conduct a DDOS attack!")
             else:
               dest = input("Destination node: ")
               dest_node = node_configurations[dest]
   
               node.ddos_attack(dest_node.ip_address)
        elif command == "exit":
           record_node_running(node_type, False)
           node.stop_receiving()
           print("Goodbye!")
           exit()
    
