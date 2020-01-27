#!/bin/bash

# This script implements the functionalities of an EveryWAN Edge Device

# General imports
source devid.sh
source hostname.sh
source nodes.sh
source ips.sh
source interfaces.sh

# Contoller hostname
CONTROLLER=$1
# NAT discovery server hostname
NAT=$2
# Neighbor through which the NAT discovery request has to be sent
NAT_DISCOVERY_CLIENT=$3

# Get the IP address of the controller
CONTROLLER=${NODES[$CONTROLLER]}
# Get the IP address of the NAT discovery server
NAT=${NODES[$NAT]}
# Get the IP address of the output interface used by the NAT discovery procedure
NAT_DISCOVERY_CLIENT=${IPS[${INTERFACES[$NAT_DISCOVERY_CLIENT]}]}

# Generate the device configuration
CONFIG='{"id":"'$DEVICEID'","features":[{"name":"gRPC","port":12345},{"name":"SSH","port":22}]}'
# Export the configuration
jq -n ${CONFIG} > /tmp/config-${HOSTNAME}.json

# Start etherws virtual switch
etherws sw
# Wait for the controller getting ready
sleep 15
# Start the southbound gRPC server
python -m srv6_sdn_data_plane.southbound.grpc.sb_grpc_server --debug &
# Wait
sleep 5
# Start the registration client
python -m pymerang.pymerang_client --config-file /tmp/config-${HOSTNAME}.json --nat-discovery-server-ip $NAT --nat-discovery-client-ip $NAT_DISCOVERY_CLIENT --nat-discovery-client-port 4789 --server-ip $CONTROLLER --server-port 50061 --token-file ./token &
