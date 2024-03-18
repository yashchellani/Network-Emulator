#!/bin/bash

# Array containing the names of all the Python script files
files=("data_link.py" "data_link_2.py" "router.py" "node1.py" "node2.py")

# Function to terminate a process by its name
terminate_process() {
    pid=$(pgrep -f "$1")
    if [ -n "$pid" ]; then
        kill "$pid"
    fi
}

# Iterate over the files array and terminate the corresponding processes
for file in "${files[@]}"; do
    terminate_process "$file"
done
