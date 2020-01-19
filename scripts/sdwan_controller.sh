#!/bin/bash

# This script implements the functionalities of a SD-WAN controller

# General imports
source nodes.sh
source hostname.sh

# Get the names of the hosts to which the controller must connect to
# extract the topology
nodes=( "$@" )

# Build the mapping IP-port
ips=""
for node in ${nodes}
do
	ips+=${NODES[${node}]}-2606,
done
# Delete trailing comma
ips="${ips:0:-1}"

# Start the etherws virtual switch
etherws sw
# Start the SD-WAN controller
python -m srv6_sdn_control_plane.srv6_controller --ips $ips --period 10 --topology /tmp/topo.json --topo-graph /tmp/topo_graph.svg --sb-interface gRPC --nb-interface gRPC --grpc-server-ip :: --grpc-server-port 12345 --pymerang-server-ip ${NODES[$HOSTNAME]} --pymerang-server-port 50061
