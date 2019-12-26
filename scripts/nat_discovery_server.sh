#!/bin/bash

source nodes.sh
source hostname.sh

ip=${NODES[$HOSTNAME]}

if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo IPv4
  server_ip="0.0.0.0"
else
  echo IPv6
  server_ip="::"
fi

python -m nat_utils.nat_discovery_server --nat-discovery-server-ip ${server_ip}
