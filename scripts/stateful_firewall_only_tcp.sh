#!/bin/bash

# Script to configure a stateful firewall allowing only TCP traffic

# General imports
source interfaces.sh

# Internal interface
int_interface=${INTERFACES[$1]}
# External interface
ext_interface=${INTERFACES[$2]}

# First cleanup everything
iptables -t filter -F
iptables -t filter -X
ip6tables -t filter -F
ip6tables -t filter -X

# Default drop all forwarded packets
iptables -t filter -P INPUT ACCEPT
iptables -t filter -P FORWARD DROP
iptables -t filter -P OUTPUT ACCEPT
ip6tables -t filter -P INPUT ACCEPT
ip6tables -t filter -P FORWARD DROP
ip6tables -t filter -P OUTPUT ACCEPT

# Accept connections intiated from the internal interface
iptables -t filter -A FORWARD -p tcp -i $int_interface -o $ext_interface -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -t filter -A FORWARD -p tcp -i $ext_interface -o $int_interface -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -t filter -A FORWARD -p tcp -i $int_interface -o $ext_interface -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
ip6tables -t filter -A FORWARD -p tcp -i $ext_interface -o $int_interface -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
