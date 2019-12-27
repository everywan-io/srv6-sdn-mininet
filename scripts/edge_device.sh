#!/bin/bash

#NAME=$1
#ID=$2

CONTROLLER=$1

source devid.sh
source hostname.sh
#source neighs.sh
source nodes.sh

echo $CONTROLLER
echo $DEVICEID
echo ${NEIGHS[$CONTROLLER]}

#CONTROLLER=${NEIGHS[$CONTROLLER]}

CONTROLLER=${NODES[$CONTROLLER]}

JSON_STRING='{"id":"'$DEVICEID'","features":[{"name":"gRPC","port":12345},{"name":"SSH","port":22}]}' #,"features":"[{"name": "gRPC", "port": 12345}, {"name": "SSH", "port": 22}]"}'

jq -n ${JSON_STRING} > /tmp/config-${HOSTNAME}.json

echo ${PATH}
echo ${CONTROLLER}

#echo $JSON_STRING > device.json
#cp device_config.json /tmp/config-$NAME.json

#jq --arg id "$ID" '.address = $id' /tmp/config/config-$NAME.json > "$tmp" && mv "$tmp" /tmp/config/config-$NAME.json

sleep 5
python -m pymerang.pymerang_client --config-file /tmp/config-${HOSTNAME}.json --nat-discovery-server-ip $CONTROLLER --server-ip $CONTROLLER
sleep 5
python -m srv6_sdn_data_plane.southbound.grpc.sb_grpc_server --debug