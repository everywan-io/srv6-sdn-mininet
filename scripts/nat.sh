#!/bin/bash

# Script to set configure NAT

# Take arguments from the command-line
#interface=$1

source interfaces.sh

interface=${INTERFACES[$1]}

# First cleanup everything
ip6tables -t nat -F
ip6tables -t nat -X

# Configure the NAT
iptables -t nat -A POSTROUTING -o $interface -j MASQUERADE
ip6tables -t nat -A POSTROUTING -o $interface -j MASQUERADE
