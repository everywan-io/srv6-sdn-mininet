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
# IP of the interface facing the public net
IP_INTERFACE=${IPS[$INPUT_INTERFACE]}

# Ful Cone NAT
#iptables -t nat -A POSTROUTING -o $INPUT_INTERFACE -j SNAT --to-source $IP_INTERFACE
#iptables -t nat -A PREROUTING -i $INPUT_INTERFACE -p udp -j DNAT --to-destination $EDGE

# Add the port forwarding rule
iptables -t nat -I PREROUTING 1 -i $INPUT_INTERFACE -p udp --dport 33000 -j DNAT --to $EDGE:33000
iptables -t nat -I POSTROUTING 1 -o $INPUT_INTERFACE -p udp --source $EDGE --sport 33000 -j SNAT --to-source $IP_INTERFACE:33000

#iptables -t nat -A PREROUTING -i $INPUT_INTERFACE -p tcp --dport 12345 -j DNAT --to $EDGE:12345

