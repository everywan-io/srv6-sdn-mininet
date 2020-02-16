#!/bin/bash

source /home/user/Envs/srv6env/bin/activate
cd /home/user/repos/srv6-sdn-mininet
sudo /home/user/Envs/srv6env/bin/python ./srv6_mininet_extension.py --topo topo/topology_1.json --debug --ipv4
#sudo /home/user/Envs/srv6env/bin/python ./srv6_mininet_extension.py --topo topo/example_srv6_topology_small.json --debug
