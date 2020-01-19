#!/bin/bash

# This script implements the functionalities of a NAT discovery server

# General imports
source ips.sh

# Generate the list of listner IP addresses
listening_ips=""
for ip in "${IPS[@]}"
do
    listening_ips+="-L ${ip} "
done

# Start the server
turnserver -S ${listening_ips}