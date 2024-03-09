import select
import socket
import threading

# Data structures for connected devices and their group memberships
connected_devices = {}
connected_devices_lock = threading.Lock()

node_definitions = {
    "N1": 8122,
    "N2": 8123,
    "N3": 8123,
    "N4": 8123,
}

class ListenConnections(threading.Thread):
    def __init__(self, sockets):
        super().__init__()
        self.sockets = sockets  # A list of sockets to listen to

    def run(self):
        print("Waiting for devices to connect to the LAN...")

        while True:
            # The select function will block until there is at least one socket ready for processing
            readable, _, _ = select.select(self.sockets, [], [])
            for ready_socket in readable:
                client, address = ready_socket.accept()
                with connected_devices_lock:
                    local_address = client.getsockname()  # This returns a tuple (host, port)
                    local_port = local_address[1]
                    if local_port not in connected_devices:
                        connected_devices[local_port] = [client]
                    else:
                        connected_devices[local_port].append(client)
                ReceiveMessage(client_and_address=(client, address)).start()

class ReceiveMessage(threading.Thread):
    def __init__(self, client_and_address):
        threading.Thread.__init__(self)
        self.client, self.address = client_and_address

    def run(self):
        try:
            while True:
                received_message = self.client.recv(1024)
                if not received_message:
                    break

                print(f"Received from {self.address}: {received_message}")
                print(f"Connected devices: {connected_devices}")

                received_message = received_message.decode("utf-8")
                src_mac, dest_mac, data_length, data = received_message.split(' ', 3)

                self.broadcast_to_group(received_message, dest_mac)

        except Exception as e:
            print("Exception occurred: ", e)
        finally:
            with connected_devices_lock:
                print(f"Client {self.address} disconnected")
                self.client.close()

    def broadcast_to_group(self, message, dest_mac):
        with connected_devices_lock:
            receiver_port = node_definitions[dest_mac]
            if receiver_port in connected_devices:
                for target_socket in connected_devices[receiver_port]: # Broadcast to all devices in the subnet
                    print(f"\nBroadcasting to {target_socket.getpeername()}: {message}")
                    try:
                        target_socket.sendall(message.encode("utf-8"))
                    except Exception as e:
                        print(f"Failed to send message to {target_socket.getpeername()}: {e}")
