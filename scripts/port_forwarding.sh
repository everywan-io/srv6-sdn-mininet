#!/bin/bash

# This script install a port forwarding on the NAT to allow incoming connections
# to a given host on a given port

# General imports
source hostname.sh
source nodes.sh
source ips.sh
source interfaces.sh

# Name of the neighbor on the public net
INPUT_INTERFACE=$1
# Name of the host on the private net
EDGE=$2
# IP address of the host on the private net
EDGE=${NODES[$EDGE]}
# Name of the interface facing the public net
INPUT_INTERFACE=${INTERFACES[$INPUT_INTERFACE]}

# Add the port forwarding rule
iptables -t nat -A PREROUTING -i $INPUT_INTERFACE -p udp --dport 4789 -j DNAT --to $EDGE:4789

