#!/bin/bash

# Script to configure a stateful firewall

# Take arguments from the command-line
#int_interface=$1
#ext_interface=$2

source interfaces.sh

int_interface=${INTERFACES[$1]}
ext_interface=${INTERFACES[$2]}

# First cleanup everything
ip6tables -t filter -F
ip6tables -t filter -X

# Default drop all forwarded packets
ip6tables -t filter -P INPUT ACCEPT
ip6tables -t filter -P FORWARD DROP
ip6tables -t filter -P OUTPUT ACCEPT

# Accept connections intiated from the internal interface
ip6tables -t filter -A FORWARD -i $int_interface -o $ext_interface -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
ip6tables -t filter -A FORWARD -i $ext_interface -o $int_interface -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
