#!/bin/bash

#source neighs.sh
source nodes.sh
source hostname.sh

ips=""

#for neigh in ${NEIGHS[@]}
#do
#  ips+=${neigh}-2606,
#done

#ips="${ips:0:-1}"

nodes=( "$@" )

echo $nodes
echo ${NODES[$@]}


for node in ${nodes}
do
	echo ${node}
	ips+=${NODES[${node}]}-2606,
done

ips="${ips:0:-1}"

echo $PATH
#echo $NEIGHS
echo $ips

#python -m srv6_sdn_control_plane.srv6_controller --ips $ips --period 10 --topology /tmp/topo.json --topo-graph /tmp/topo_graph.svg --sb-interface gRPC --nb-interface gRPC --grpc-server-ip :: --grpc-server-port 12345
python -m srv6_sdn_control_plane.srv6_controller --ips $ips --period 10 --topology /tmp/topo.json --topo-graph /tmp/topo_graph.svg --sb-interface gRPC --nb-interface gRPC --grpc-server-ip :: --grpc-server-port 12345 --pymerang-server-ip ${NODES[$HOSTNAME]} --pymerang-server-port 50061
#python -m nat_utils.nat_discovery_server
