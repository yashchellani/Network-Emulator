import socket
import threading
from time import sleep,time

class Node:
    def __init__(self, ip_address, mac_address, firewall=None, ids=None):
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.data_link_address = ('localhost', 8122) if mac_address == 'N1' else ('localhost', 8123)
        self.data_link_socket = None
        self.running = True
        self.receiving_thread = None
        self.firewall = firewall
        self.ids = ids
        self.ids_lock = threading.Lock()
        

    def connect_to_data_link(self):
        """Establishes a connection to the data link server."""
        self.data_link_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.data_link_socket.connect(self.data_link_address)
        print(f"\n{self.mac_address} connected to data link")

    def send_data(self, data, dest_mac, dest_ip):
        """
        Emulates sending data over Ethernet to a specific destination.
        """
        ethernet_frame = self._construct_ethernet_frame(dest_mac, data)
        try:
            self.data_link_socket.send(ethernet_frame)
            print(f"\nSent data to {dest_mac}: {ethernet_frame}")
        except ConnectionAbortedError as e:
            print(f"Failed to send data, connection was aborted: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def start_receiving(self):
        """Start a new thread to listen for incoming messages."""
        self.data_link_socket.settimeout(5.0)  # Set the timeout for blocking socket operations
        self.receiving_thread = threading.Thread(target=self.receive_data)
        self.receiving_thread.start()

    def receive_data(self):
        """Continuously listen for incoming data and print it."""
        self.data_link_socket.settimeout(5.0)  # Setting the timeout here as an example
        try:
            while self.running:
                try:
                    data, addr = self.data_link_socket.recvfrom(1024)  # Buffer size of 1024 bytes
                    
                    if self.ids:
                        print(f"\nAnalyzing packet: {data}")
                        with self.ids_lock:  # Acquire the lock
                            self.ids.analyze_packet(data)

                    src_mac, dest_mac, data_length, data = self._parse_ethernet_frame(data)
                    print(f"\nReceived data: {data} for {dest_mac} and I am {self.mac_address}")

                    if self.firewall and self.firewall.is_mac_blocked(src_mac):
                        print(f"IP address {addr[0]} is blocked. Dropping data from {src_mac} to {dest_mac}")
                        continue


                    if dest_mac == self.mac_address:
                        print(f"\nYAYYYY Node {self.mac_address} - Received data: {data} from {src_mac}")
                        self._process_received_data(data, src_mac)
                    else:
                        if hasattr(self, 'sniff_traffic'):
                            print(f"Sniffing from {src_mac} to {dest_mac}")
                            if self.sniffing_enabled:
                                self.sniff_traffic(data)
                        else:   
                            print(f"\nData not for me {self.mac_address}. Dropping data from {src_mac} to {dest_mac}.")
                        

                except socket.timeout:
                    break

        except Exception as e:
            self.running = False

    def stop_receiving(self):
        """Stop listening for incoming data."""
        self.running = False
        sleep(1)
        try:
        # Shutdown the socket connection before closing
            self.data_link_socket.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            print(f"Error shutting down the socket: {e}")
        finally:
            self.data_link_socket.close()
        self.receiving_thread.join()

    def _construct_ethernet_frame(self, dest_mac, data):
        """
        Constructs an Ethernet frame with source and destination MAC addresses and data.
        """
        data_length = len(data)
        ethernet_frame = f"{self.mac_address} {dest_mac} {data_length} {data}"
        return ethernet_frame.encode('utf-8')

    def _parse_ethernet_frame(self, frame):
        """
        Parses an Ethernet frame into its components.
        """
        frame = frame.decode('utf-8')
        src_mac, dest_mac, data_length, data = frame.split(' ', 3)
        return src_mac, dest_mac, int(data_length), data

    def _process_received_data(self, data, src_mac):
        """
        Placeholder method for processing received data. To be overridden in subclasses.
        """
        print(f"Data from {src_mac}: {data}")

    def connect_to_node(self, node_mac, node_ip):
        """
        Connects to another node by storing its MAC and IP addresses.
        """
        self.connected_nodes[node_mac] = node_ip

    def disconnect_from_node(self, node_mac):
        """
        Disconnects from another node by removing its MAC address.
        """
        if node_mac in self.connected_nodes:
            del self.connected_nodes[node_mac]    
                
     
    def ping(self, dest_ip, count):
        """
        Emulates pinging IP addresses with ICMP packets to a specific destination.
        """
        for _ in range(count):
            try:
                # Send ICMP ping request
                icmp_request = "PING"
                self.send_data(data=icmp_request, dest_mac=self.mac_address, dest_ip=dest_ip)

                # Record the time when the ping was sent
                time_ping_sent = time()

                # Wait for ICMP ping response
                response_received = False
                timeout = 5  # Adjust timeout as needed
                start_time = time()
                while not response_received and time() - start_time < timeout:
                    try:
                        # Receive the ICMP ping response
                        data, _ = self.data_link_socket.recvfrom(1024)  # Adjust buffer size as needed
                        
                        # Record the time when the ping response was received
                        time_ping_echo_received = time()
                        
                        # Extract source IP address from the received data
                        src_ip = data.decode('utf-8')
                        
                        # Check if the response is from the destination IP address
                        if src_ip == dest_ip:
                            # Calculate round-trip time (RTT)
                            rtt = time_ping_echo_received - time_ping_sent
                            print(f"Response received from {dest_ip}: RTT={rtt:.6f} seconds")
                            response_received = True
                    except socket.timeout:
                        pass

                if not response_received:
                    print(f"No response received from {dest_ip} within {timeout} seconds.")
                    
                # Sleep between pings (if necessary)
                sleep(1)
            except ConnectionAbortedError as e:
                print(f"Failed to send data, connection was aborted: {e}")
            except Exception as e:
                print(f"An unexpected error occurred: {e}")



    def send_ping(self, dest_ip):
        """
        Constructs and sends a ping packet to the specified destination IP address.
        """
        ping_packet = f"{self.ip_address} {dest_ip} {time()}"
        self.data_link_socket.sendto(ping_packet.encode(), ('localhost', 8122))


    def respond_to_ping(self):
        """
        Method to respond to ping requests.
        """
        # Here you can construct a response and send it back to the source MAC address
        response_data = "Response to ping request"
        self.send_data(response_data, self.mac_address, self.ip_address)

        
 

   