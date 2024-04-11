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
    "R1": 8122,
    "R2": 8123
}

class ListenConnections(threading.Thread):
    def __init__(self, sockets):
        super().__init__()
        self.sockets = sockets  # A list of sockets to listen to
        self.listeners = []
        self.running = True

    def run(self):
        print("Waiting for devices to connect to the LAN...")

        while self.running:
            # The select function will block until there is at least one socket ready for processing
            readable, _, _ = select.select(self.sockets, [], [])
            for ready_socket in readable:
                try:
                    client, address = ready_socket.accept()
                    with connected_devices_lock:
                        local_address = client.getsockname()  # This returns a tuple (host, port)
                        local_port = local_address[1]
                        if local_port not in connected_devices:
                            connected_devices[local_port] = [client]
                        else:
                            connected_devices[local_port].append(client)
                        
                    receiver_thread = ReceiveMessage(client_and_address=(client, address), local_port=local_port)
                    receiver_thread.start()
                    self.listeners.append(receiver_thread)
                except Exception as e:
                    break
    
    def stop(self):
        self.running = False
        for listener in self.listeners:
            if listener.is_alive():
                listener.join()
        for socket in self.sockets:
            socket.close()

class ReceiveMessage(threading.Thread):
    def __init__(self, client_and_address, local_port):
        threading.Thread.__init__(self)
        self.client, self.address = client_and_address
        self.local_port = local_port

    def run(self):
        try:
            while True:
                received_message = self.client.recv(1024)
                if not received_message:
                    break

                received_message = received_message.decode("utf-8")
                src_mac, dest_mac, data_length, ethertype, data = received_message.split(' ', 4)
                src_mac = src_mac.replace(';', '')

                # If broadcast address, send it back to the subnet group of the src mac
                if dest_mac == "FF":
                    dest_mac = src_mac

                self.broadcast_to_group(received_message, dest_mac)

        except Exception as e:
            print("Data link exception occurred: ", e)
        finally:
            with connected_devices_lock:
                print(f"Client {self.address} disconnected")
                connected_devices[self.local_port].remove(self.client)
                self.client.close()

    def broadcast_to_group(self, message, dest_mac):
        with connected_devices_lock:
            receiver_port = node_definitions[dest_mac]
            if receiver_port in connected_devices:
                for target_socket in connected_devices[receiver_port]: # Broadcast to all devices in the subnet
                    print(f"[DATA LINK] Broadcasting to {target_socket.getpeername()}: {message}")
                    try:
                        target_socket.sendall(message.encode("utf-8"))
                    except Exception as e:
                        print(f"Failed to send message to {target_socket.getpeername()}: {e}")
