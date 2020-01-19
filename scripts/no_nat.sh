#!/bin/bash

# Script used to clear the firewall rules

# Cleanup everything in the NAT table
iptables -t nat -F
iptables -t nat -X
ip6tables -t nat -F
ip6tables -t nat -X