#!/bin/bash

# Run data_link.py in a new terminal
osascript -e 'tell app "Terminal" to do script "/usr/bin/python3 /path/to/router/data_link.py"'

# Run data_link_2.py in a new terminal
osascript -e 'tell app "Terminal" to do script "/usr/bin/python3 /path/to/router/data_link_2.py"'

# Run router.py in a new terminal
osascript -e 'tell app "Terminal" to do script "/usr/bin/python3 /path/to/router/router.py"'

# Run node1.py in a new terminal
osascript -e 'tell app "Terminal" to do script "/usr/bin/python3 /path/to/old_stuffs/node1.py"'

# Run node2.py in a new terminal
osascript -e 'tell app "Terminal" to do script "/usr/bin/python3 /path/to/old_stuffs/node2.py"'
