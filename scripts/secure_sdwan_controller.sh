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

# Get the IP address of the controller
controller_ip=${NODES[$HOSTNAME]}

# Start the etherws virtual switch
etherws sw
# In our experiment, the controller is also our certification authority (CA)
# Generate CA key
openssl genrsa -out ca.key 2048
# Generate CA certificate
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN=example.com" 
# Copy the CA certificate to /tmp, so it will be easy to find it for the edge devices
cp ca.crt /tmp/ca.crt
# Generate server key
openssl genrsa -out server.key 2048
# Generate server certificate signing request
openssl req -new -key server.key -out server.csr -subj "/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN=example.com" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:example.com,DNS:${NODES[$HOSTNAME]}"))
# Generate server certificate
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt -extfile <(printf "basicConstraints = CA:FALSE\nkeyUsage = nonRepudiation, digitalSignature, keyEncipherment\nsubjectAltName = @alt_names\n[alt_names]\nDNS.1=example.com\nDNS.2=${NODES[$HOSTNAME]}")
# Start the Certification Authority
python -m pymerang.cert_authority --server-ip :: --server-port 54322 --secure --ca-cert server.crt --ca-key server.key &
# Start the SD-WAN controller
python -m srv6_sdn_control_plane.srv6_controller --ips $ips --period 10 --topology /tmp/topo.json --topo-graph /tmp/topo_graph.svg --sb-interface gRPC --nb-interface gRPC --grpc-server-ip :: --grpc-server-port 54321 --pymerang-server-ip ${NODES[$HOSTNAME]} --pymerang-server-port 50061 -s -x --sb-server-cert server.crt --sb-server-key server.key --nb-server-cert server.crt --nb-server-key server.key --client-cert /tmp/ca.crt &
