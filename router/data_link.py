import socket
import threading

# Open socket
data_link = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
data_link.bind(("localhost", 8122))

# Data structures for connected devices and their group memberships
connected_devices = set()
group_memberships = {}  # Maps client addresses to group IDs
connected_devices_lock = threading.Lock()

# Open connections to the socket
data_link.listen(4)

class ListenConnections(threading.Thread):
    def __init__(self, group_definitions):
        super().__init__()
        self.group_definitions = group_definitions
        
    def run(self):
        print("Waiting for devices to connect to the LAN...")

        while True:
            client, address = data_link.accept()
            group_id = input(f"Assign a group ID for {address}: ")  # Manually assign group ID upon connection

            with connected_devices_lock:
                connected_devices.add((client, address))
                group_memberships[address] = group_id
            
            print(f"New client connected from {address} to group {group_id}!")
            ReceiveMessage(client_and_address=(client, address), group_id=group_id).start()

class ReceiveMessage(threading.Thread):
    def __init__(self, client_and_address, group_id):
        threading.Thread.__init__(self)
        self.client, self.address = client_and_address
        self.group_id = group_id

    def run(self):
        print(f"Listening for messages from {self.address} in group {self.group_id}...")
        try:
            while True:
                received_message = self.client.recv(1024)
                if not received_message:
                    break

                received_message = received_message.decode("utf-8")
                print(f"Received from {self.address}: {received_message}")

                # Broadcast to all devices in the same group
                self.broadcast_to_group(received_message)

        except Exception as e:
            print("Exception occurred: ", e)
        finally:
            with connected_devices_lock:
                connected_devices.remove((self.client, self.address))
                del group_memberships[self.address]
                print(f"Client {self.address} disconnected")
                self.client.close()

    def broadcast_to_group(self, message):
        with connected_devices_lock:
            for device, address in connected_devices:
                # Check if the device is in the same group
                if group_memberships.get(address) == self.group_id:
                    try:
                        device.sendall(bytes(message, "utf-8"))
                    except Exception as e:
                        print(f"Failed to send message to {address}: {e}")

