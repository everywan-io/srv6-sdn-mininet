#!/bin/bash

# Script to configure a stateless firewall

# First cleanup everything
ip6tables -t filter -F
ip6tables -t filter -X

# Default drop all forwarded packets
ip6tables -t filter -P INPUT ACCEPT
ip6tables -t filter -P FORWARD DROP
ip6tables -t filter -P OUTPUT ACCEPT

# Accept TCP traffic
ip6tables -t filter -A FORWARD -p tcp -j ACCEPT