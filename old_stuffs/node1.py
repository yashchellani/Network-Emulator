import socket
import time 

node_1_ip = "\x1a"
node_1_mac = "N1"

router = ("localhost", 8122)

node_1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
time.sleep(1)
node_1.connect(router)

while True:
    # received_message = node_1.recv(1024)
    message = input("\nEnter the text message to send: ")
    packet = message
    node_1.sendto(bytes(packet, "utf-8"), router) 