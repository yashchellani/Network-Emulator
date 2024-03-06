import socket
import time 

node_2_ip = "\x2a"
node_2_mac = "N2"

router = ("localhost", 8123)

node_2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
time.sleep(1)
node_2.connect(router)

while True:
    message = input("\nEnter the text message to send: ")
    packet = message
    node_2.sendto(bytes(packet, "utf-8"), router) 