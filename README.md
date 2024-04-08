# INSTRUCTION
1. Run `router_main.py` in one terminal
2. Open a new terminal for each node then run `node_main.py`
3. Make sure each of your terminals are running different nodes (e.g. one terminal for node1, another for node2, etc.)

# TO-DO
- [x] Make code less spaghetti
- [x] Allow nodes to accept messages from their LAN as well
- [] Fix `router_main.py` to exit gracefully
- [x] Fix recvfrom issues (how to clear previous messages from buffer?)
- Implement protocols and functionalities: 
    - [x] ARP
    - [x] Kill
    - [x] Ping
    - [x] Option to drop packets not meant for it
    - [x] Router encapsulation
    - [x] Firewall
    - [x] IP Spoofing from Node 2
- [] Implement bonus functionalities
    - [x] ARP Spoofing
