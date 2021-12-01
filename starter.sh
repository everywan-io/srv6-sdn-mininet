#!/bin/bash

source /home/rose/workspace/everywan/.everywan-venv/bin/activate
cd /home/rose/workspace/everywan/srv6-sdn-mininet
#sudo /home/rose/workspace/everywan/.everywan-venv/bin/python ./srv6_mininet_extension.py --topo topo/topology_h_multisub.json --debug --ipv4
sudo /home/rose/workspace/everywan/.everywan-venv/bin/python ./srv6_mininet_extension.py --topo topo/topology_h_multisub_ipv6.json --debug
#sudo /home/user/Envs/srv6env/bin/python ./srv6_mininet_extension.py --topo topo/example_srv6_topology_small.json --debug
