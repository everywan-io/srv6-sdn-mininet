#!/bin/bash

# Script to configure NAT masquerade (symmetric NAT)

# General imports
source interfaces.sh

# Name of the output interface used by the NAT
interface=${INTERFACES[$1]}

# First cleanup everything
#iptables -t nat -F
#iptables -t nat -X
#ip6tables -t nat -F
#ip6tables -t nat -X

# Configure the NAT
iptables -t nat -A POSTROUTING -o $interface -j MASQUERADE
ip6tables -t nat -A POSTROUTING -o $interface -j MASQUERADE
