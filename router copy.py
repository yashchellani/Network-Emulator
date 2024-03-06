# UNUSED


# import socket
# import time
# import threading

# ###############################
# # OPEN SOCKETS
# ###############################

# # Open TCP (SOCK_STREAM) port for Node 1
# router_1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# router_1.bind(("localhost", 8100))

# # Open TCP (SOCK_STREAM) port for Node 2 & 3
# router_2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# router_2.bind(("localhost", 8200))

# ###############################
# # SHARED RESOURCES
# ###############################

# # Hardcoded values -- MOVE TO ANOTHER FILE LATER
# router_1_mac = "R1"
# router_1_ip = "\x11"
# router_2_mac = "R2"
# router_2_ip = "\x21"

# node_1_ip = "\x1a"
# node_1_mac = "N1"
# node_2_ip = "\x2a"
# node_2_mac = "N2"
# node_3_ip = "\x2b"
# node_3_mac = "N3"

# # ARP Table
# ARP_table = dict()
# arp_mutex = threading.Lock()

# # List of R1 clients
# router_1_clients = set()
# router_1_mutex = threading.Lock()

# # List of R2 clients
# router_2_clients = set()
# router_2_mutex = threading.Lock()

# ###############################
# # PROTOCOLS
# ###############################
# def arp_broadcast(sourceIP, destIP, sourceMAC):
#     packet = sourceIP + destIP + "2" + sourceMAC + "FF" + "ARP Broadcast"

# def encapsulate():
#     pass

# ###############################
# # R1
# ###############################

# # Open connections
# router_1.listen(4)

# # Thread to listen for connections for R1
# class R1Listen(threading.Thread):
#     def run(self):
#         print("Waiting to receive connections from Interface R1...")

#         while True:
#             new_client_and_address = router_1.accept()
#             with router_1_mutex:
#                 router_1_clients.add(new_client_and_address)
#             print("New client connected!")
#             ReceiveMessage(client_and_address=new_client_and_address, router_interface="R1").start()

# ###############################
# # R2
# ###############################

# # Open connections
# router_2.listen(4)

# # Thread to listen for connections for R2
# class R2Listen(threading.Thread):
#     def run(self):
#         print("Waiting to receive connections from Interface R2...")

#         while True:
#             new_client_and_address = router_2.accept()
#             with router_2_mutex:
#                 router_2_clients.add(new_client_and_address)
#             print("New client connected!")
#             ReceiveMessage(client_and_address=new_client_and_address, router_interface="R2").start()

# ###############################
# # INDIVIDUAL CONNECTIONS
# ###############################
            
# # Thread to listen for messages on individual connections
# class ReceiveMessage(threading.Thread):
#     def __init__(self, client_and_address, router_interface):
#         threading.Thread.__init__(self)
#         self.client_and_address = client_and_address
#         self.client = client_and_address[0]
#         self.client_address = client_and_address[1]
#         self.router_interface = router_interface

#     def run(self):
#         print("Waiting to receive message...")
#         try:
#             while(True):
#                 received_message = self.client.recv(1024)
#                 if not received_message:
#                     break
#                 received_message = received_message.decode("utf-8")
#                 print(received_message)
#         except Exception as e:
#             print("Exception has occurred: ", e)
#         finally:
#             if self.router_interface == "R1":
#                 with router_1_mutex:
#                     router_1_clients.remove(self.client_and_address)
#                     print("Client disconnected from R1")
#                     self.client.close()
#             elif self.router_interface == "R2":
#                 with router_2_mutex:
#                     router_2_clients.remove(self.client_and_address)
#                     print("Client disconnected from R2")
#                     self.client.close()

# ###############################
# # MAIN FUNCTION
# ###############################
                    
# if __name__ == "__main__":
#     R1_thread = R1Listen()
#     R1_thread.start()
#     R2_thread = R2Listen()
#     R2_thread.start()