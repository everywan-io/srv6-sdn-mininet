#!/bin/bash

# Script used to clear the firewall rules

# Cleanup everything in the filter table
iptables -t filter -F
iptables -t filter -X
ip6tables -t filter -F
ip6tables -t filter -X