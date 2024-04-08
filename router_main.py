from nodes.node_types import BasicNode, MaliciousNode, FirewallNode
import json
import socket
from security.firewall import Firewall
from security.ids import IDS

import socket
from router import Router
from router.data_link import ListenConnections

from time import sleep
    
if __name__ == '__main__':
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

  router = Router(interface_configs=[
    {'ip': '\x11', 'mac': 'R1', 'network': '\x10/4', 'data_link_address': ('localhost', 8122)}, # old network: 192.168.1.0/24
    {'ip': '\x21', 'mac': 'R2', 'network': '\x20/4', 'data_link_address': ('localhost', 8123)} # old network: 192.168.2.0/24
  ])
  
  
  router.connect_to_data_link()
  router.start_receiving()
      