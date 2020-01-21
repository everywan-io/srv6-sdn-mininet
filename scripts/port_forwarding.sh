#!/bin/bash

INPUT_INTERFACE=$1
EDGE=$2

source hostname.sh
source nodes.sh
source ips.sh
source interfaces.sh


EDGE=${NODES[$EDGE]}
INPUT_INTERFACE=${INTERFACES[$INPUT_INTERFACE]}

IP_INTERFACE=${IPS[$INPUT_INTERFACE]}

echo $EDGE
echo $INPUT_INTERFACE
echo $IP_INTERFACE

# Ful Cone NAT
#iptables -t nat -A POSTROUTING -o $INPUT_INTERFACE -j SNAT --to-source $IP_INTERFACE
#iptables -t nat -A PREROUTING -i $INPUT_INTERFACE -p udp -j DNAT --to-destination $EDGE


iptables -t nat -I PREROUTING 1 -i $INPUT_INTERFACE -p udp --dport 40000 -j DNAT --to $EDGE:4789
iptables -t nat -I POSTROUTING 1 -o $INPUT_INTERFACE -p udp --source $EDGE --sport 4789 -j SNAT --to-source $IP_INTERFACE:40000

#iptables -t nat -A PREROUTING -i $INPUT_INTERFACE -p tcp --dport 12345 -j DNAT --to $EDGE:12345

