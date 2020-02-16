#!/bin/bash

# Script to configure a stateless firewall allowing only TCP traffic

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

# Accept TCP traffic
iptables -t filter -A FORWARD -p tcp -j ACCEPT
ip6tables -t filter -A FORWARD -p tcp -j ACCEPT