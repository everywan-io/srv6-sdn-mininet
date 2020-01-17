#!/bin/bash

#NAME=$1
#ID=$2

CONTROLLER=$1
NAT=$2
NAT_DISCOVERY_CLIENT=$3

source devid.sh
source hostname.sh
#source neighs.sh
source nodes.sh
source ips.sh
source interfaces.sh

echo $CONTROLLER
echo $DEVICEID
echo ${NEIGHS[$CONTROLLER]}

#CONTROLLER=${NEIGHS[$CONTROLLER]}

CONTROLLER=${NODES[$CONTROLLER]}
NAT=${NODES[$NAT]}
NAT_DISCOVERY_CLIENT=${IPS[${INTERFACES[$NAT_DISCOVERY_CLIENT]}]}
echo "Wnat"
echo $NAT_DISCOVERY_CLIENT

JSON_STRING='{"id":"'$DEVICEID'","features":[{"name":"gRPC","port":12345},{"name":"SSH","port":22}]}' #,"features":"[{"name": "gRPC", "port": 12345}, {"name": "SSH", "port": 22}]"}'

jq -n ${JSON_STRING} > /tmp/config-${HOSTNAME}.json

echo ${PATH}
echo "CONTROLLER11111111111111111111"
echo ${CONTROLLER}



#if [[ $CONTROLLER =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
#  echo IPv4
#  nat_discovery_client="0.0.0.0"
#else
#  echo IPv6
#  nat_discovery_client="::"
#fi

#echo $JSON_STRING > device.json
#cp device_config.json /tmp/config-$NAME.json

#jq --arg id "$ID" '.address = $id' /tmp/config/config-$NAME.json > "$tmp" && mv "$tmp" /tmp/config/config-$NAME.json

#python -m pymerang.etherws sw
etherws sw
#sleep 5
sleep 15
echo --nat-discovery-server-ip $NAT
python -m srv6_sdn_data_plane.southbound.grpc.sb_grpc_server --debug &
sleep 5
python -m pymerang.pymerang_client --config-file /tmp/config-${HOSTNAME}.json --nat-discovery-server-ip $NAT --nat-discovery-client-ip $NAT_DISCOVERY_CLIENT --nat-discovery-client-port 4789 --server-ip $CONTROLLER --server-port 50061 &