#!/bin/bash

# common paths
BASE_PATH="/Users/yashchellani/Desktop/Y4S2/CS441/Project/cs441/"
OLD_STUFFS_PATH="${BASE_PATH}old_stuffs/"

# Run data_link.py in a new terminal
osascript -e "tell app \"Terminal\" to do script \"/usr/bin/python3 ${OLD_STUFFS_PATH}data_link.py\""

# Run data_link_2.py in a new terminal
osascript -e "tell app \"Terminal\" to do script \"/usr/bin/python3 ${OLD_STUFFS_PATH}data_link_2.py\""

# Run router.py in a new terminal
osascript -e "tell app \"Terminal\" to do script \"/usr/bin/python3 ${OLD_STUFFS_PATH}router.py\""

# Run node1.py in a new terminal
osascript -e "tell app \"Terminal\" to do script \"/usr/bin/python3 ${OLD_STUFFS_PATH}node1.py\""

# Run node2.py in a new terminal
osascript -e "tell app \"Terminal\" to do script \"/usr/bin/python3 ${OLD_STUFFS_PATH}node2.py\""
