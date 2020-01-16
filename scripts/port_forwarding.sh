#!/bin/bash

INPUT_INTERFACE=$1
EDGE=$2

source hostname.sh
source nodes.sh
source ips.sh
source interfaces.sh


EDGE=${NODES[$EDGE]}
INPUT_INTERFACE=${INTERFACES[$INPUT_INTERFACE]}

echo $EDGE
echo $INPUT_INTERFACE

iptables -t nat -A PREROUTING -i $INPUT_INTERFACE -p udp --dport 4789 -j DNAT --to $EDGE:4789

