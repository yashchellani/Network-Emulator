from nodes.node_types import BasicNode, MaliciousNode, FirewallNode
from router.router import Router
from security.firewall import Firewall
from security.ids import IDS
from router.data_link import ListenConnections
import json
from time import sleep
import multiprocessing

def load_firewall_rules(filepath="config/rules.json"):
    with open(filepath, 'r') as file:
        data = json.load(file)
        return data["rules"]


def start_router(interface_configs):
    router = Router(interface_configs=interface_configs)
    router.connect_to_data_link()
    router.start_receiving()
    

def start_node(i, firewall, ids, message_queue):
    if i == 1:
        node = BasicNode(ip_address='\x1A', mac_address='N1', message_queue=message_queue)
        print("Node 1 created")
    elif i == 2:
        node = MaliciousNode(ip_address='\x2A', mac_address='N2', message_queue=message_queue)
        print("Node 2 created")
    elif i == 3:
        node = FirewallNode(ip_address='\x2B', mac_address='N3', message_queue=message_queue, firewall=firewall, ids=ids)
        print("Node 3 created")
    elif i == 4:
        node = BasicNode(ip_address='\x2C', mac_address='N4', message_queue=message_queue)
        print("Node 4 created")
    node.connect_to_data_link()
    node.start_receiving()

def start_data_link_server():
    data_link_server = ListenConnections()
    data_link_server.run()
    
def setup_network():

    data_link_server = multiprocessing.Process(target=start_data_link_server)
    data_link_server.start()
    sleep(2)

    # queue that is updated every time a device is connected to the datalink
    # data_link_events_queue = multiprocessing.Queue()

    router_process = multiprocessing.Process(target=start_router, args=(
        [
            {'ip': '\x11', 'mac': 'R1', 'network': '\x10/4', 'data_link_address': ('localhost', 8122)},
            {'ip': '\x21', 'mac': 'R2', 'network': '\x20/4', 'data_link_address': ('localhost', 8123)}
        ],
    ))
    router_process.start()
    sleep(2)

    firewall_rules = load_firewall_rules()
    firewall = Firewall(firewall_rules)
    node_queues = [multiprocessing.Queue() for _ in range(4)]
    ids = IDS(firewall)

    for i in range(1, 5):
        node_process = multiprocessing.Process(target=start_node, args=(i, firewall, ids, node_queues[i-1]))
        node_process.start()
        sleep(2)
    
    sleep(10)
    simulate_network_traffic(node_queues)

    return firewall, router_process, node_queues

def simulate_network_traffic(node_queues):
    # Example: Simulate sending a message from node 1 to node 2
    # print("Sending message from Node 1 to Node 2")
    message = {'command': "send_ip_packet", 'data': 'Hello Node2', 'dest_ip': '\x2A', 'protocol': 3}
    node_queues[0].put(message)

if __name__ == '__main__':
    setup_network()
