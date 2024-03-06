import socket
import time
import threading

# Open socket
data_link = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
data_link.bind(("localhost", 8123)) # LITERALLY THE ONLY DIFFERENCE BETWEEN DATA LINK 1 AND DATA LINK 2

# Set for connected devices
connected_devices = set()
connected_devices_lock = threading.Lock()

# Open connections to the socket
data_link.listen(4)

# Thread to listen for connections into the LAN
class ListenConnections(threading.Thread):
    def run(self):
        print("Waiting for devices to connect to the LAN...")

        while True:
            # Accept connection
            new_client_and_address = data_link.accept()

            # Add connected device into set
            with connected_devices_lock:
                connected_devices.add(new_client_and_address)
            print("New client connected!")

            # Spawn a thread to listen to the device
            ReceiveMessage(client_and_address=new_client_and_address).start()

# Thread to listen to the current devices in the LAN
class ReceiveMessage(threading.Thread):
    def __init__(self, client_and_address):
        threading.Thread.__init__(self)
        self.client_and_address = client_and_address
        self.client = client_and_address[0]
        self.client_address = client_and_address[1]

    def run(self):
        print("Waiting to receive message...")
        try:
            while(True):
                # Wait to receive message from designated client
                received_message = self.client.recv(1024)

                # If client disconnects, break out of the loop
                if not received_message:
                    break

                # Decode the bytes
                received_message = received_message.decode("utf-8")

                print(received_message)

                # Forward message to all the connected devices
                with connected_devices_lock:
                    for device in connected_devices:
                        # Don't send back to the same device that sent the message
                        if self.client_and_address == device:
                            continue
                        device[0].sendto(bytes(received_message, "utf-8"), device[1])

        except Exception as e:
            print("Exception has occurred: ", e)
        finally:
            # Disconnect client
            with connected_devices_lock:
                connected_devices.remove(self.client_and_address)
                print("Client disconnected from LAN")
                print(connected_devices)
                self.client.close()


if __name__ == "__main__":
    # Listen for connections
    listen_thread = ListenConnections()
    listen_thread.start()