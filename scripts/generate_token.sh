#!/bin/bash

# This script generates tenants for SD-WAN

# General imports
source nodes.sh
source hostname.sh

# Number of tokens to be generated
N=$1
# Get the IP address of the controller
controller_ip=${NODES[$HOSTNAME]}
# Generate the tenant configuration
CONFIG='[{"port":40000,"info":"user"}]'
echo "$CONFIG" > /tmp/tenant_config.json
# Wait for controller getting ready
sleep 5
# Generate N tokens
for (( i=1; i<=N; i++ ))
do
  # Generate the token
  token="$(python -m configure_tenant --controller-ip $controller_ip --controller-port 54321 --config-path /tmp/tenant_config.json)"
  token=${token##*TOKEN:  }
  echo "$token" > "/tmp/token-$i"
done