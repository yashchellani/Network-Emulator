import socket
import time
import threading

###############################
# OPEN SOCKETS
###############################

# Open TCP (SOCK_STREAM) port for Node 1
router_1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
router_1.bind(("localhost", 8100))

# Open TCP (SOCK_STREAM) port for Node 2 & 3
router_2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
router_2.bind(("localhost", 8200))

###############################
# SHARED RESOURCES
###############################

# Hardcoded values -- MOVE TO ANOTHER FILE LATER
router_1_mac = "R1"
router_1_ip = "\x11"
router_2_mac = "R2"
router_2_ip = "\x21"

node_1_ip = "\x1a"
node_1_mac = "N1"
node_2_ip = "\x2a"
node_2_mac = "N2"
node_3_ip = "\x2b"
node_3_mac = "N3"

# ARP Table
ARP_table = dict()
arp_mutex = threading.Lock()

# List of R1 clients
router_1_clients = set()
router_1_mutex = threading.Lock()

# List of R2 clients
router_2_clients = set()
router_2_mutex = threading.Lock()

###############################
# PROTOCOLS
###############################
def arp_broadcast(sourceIP, destIP, sourceMAC):
    packet = sourceIP + destIP + "2" + sourceMAC + "FF" + "ARP Broadcast"

def encapsulate():
    pass

###############################
# R1
###############################

# Connect to LAN 1
data_link_1 = ("localhost", 8122)
router_1.connect(data_link_1)


###############################
# R2
###############################

# Connect to LAN 2
data_link_2 = ("localhost", 8123)
router_2.connect(data_link_2)

###############################
# MAIN FUNCTION
###############################
                    
if __name__ == "__main__":
    print("Waiting for message...")
    while True:
        received_message_1 = router_1.recv(1024)
        print(received_message_1)

        received_message_2 = router_2.recv(1024)
        print(received_message_2)