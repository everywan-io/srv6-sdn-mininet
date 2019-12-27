#!/bin/bash

source /home/user/Envs/srv6env/bin/activate
cd /home/user/repos/srv6-sdn-mininet
#sudo /home/user/Envs/srv6env3/bin/python3 ./srv6_mininet_extension.py --topo topo/example_srv6_topology_small.json --controller -d
sudo /home/user/Envs/srv6env/bin/python ./srv6_mininet_extension.py --topo topo/topology_1.json --ipv4 --debug