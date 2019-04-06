#!/usr/bin/python

##############################################################################################
# Copyright (C) 2017 Pier Luigi Ventre - (CNIT and University of Rome "Tor Vergata")
# Copyright (C) 2017 Stefano Salsano - (CNIT and University of Rome "Tor Vergata")
# Copyright (C) 2017 Alessandro Masci - (University of Rome "Tor Vergata")
# www.uniroma2.it/netgroup - www.cnit.it
#
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Mininet scripts for Segment Routing IPv6
#
# @author Pier Luigi Ventre <pierventre@hotmail.com.com>
# @author Stefano Salsano <stefano.salsano@uniroma2.it>
# @author Alessandro Masci <mascialessandro89@gmail.com>

from optparse import OptionParser
from collections import defaultdict

import argparse
import os
import json
import sys

# IPaddress dependencies
import ipaddress

# Mininet dependencies
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController, OVSBridge, Node
from mininet.link import TCLink
from mininet.cli import CLI

# NetworkX dependencies
import networkx as nx
from networkx.readwrite import json_graph

# SRv6 dependencies
from srv6_topo_parser import *
from srv6_utils import *
from srv6_generators import *
from srv6_net_utils import *
import srv6_utils

# nodes.sh file for setup of the nodes
NODES_SH = "/tmp/nodes.sh"
# Topology file
TOPOLOGY_FILE = "/tmp/topology.json"
# Mapping node to management address
nodes_to_mgmt = {}
# Mapping node to loopback address
nodes_to_loopbackip = {}
# Network topology
topology = nx.MultiDiGraph()

# Create SRv6 topology and a management network for the hosts.
class SRv6Topo(Topo):

    # Init of the topology
    def __init__( self, topo="", **opts ):
        # Parse topology from json file
        parser = SRv6TopoParser(topo, verbose=False)
        parser.parse_data()
        # Save parsed data
        self.routers = parser.getRouters()
        p_routers_properties = parser.getRoutersProperties()
        self._hosts = parser.getHosts()
        p_hosts_properties = parser.getHostsProperties()
        self.controllers = parser.getControllers()
        p_controllers_properties = parser.getControllersProperties()
        self.core_links = parser.getCoreLinks()
        p_core_links_properties = parser.getCoreLinksProperties()
        self.edge_links = parser.getEdgeLinks()
        p_edge_links_properties = parser.getEdgeLinksProperties()
        self.mgmt_links = parser.getMgmtLinks()
        p_mgmt_links_properties = parser.getMgmtLinksProperties()
        # Properties generator
        if srv6_utils.IPv6_EMULATION:
            generator = IPv6PropertiesGenerator()
        else:
            generator = IPv4PropertiesGenerator()
        mgmtAllocator = MgmtAllocator()
        # Second step is the generation of the nodes parameters
        # Generation of the routers parameters
        routers_properties = generator.getRoutersProperties(self.routers)
        for router_properties, p_router_properties in zip(routers_properties, p_routers_properties):
            p_router_properties['loopback'] = router_properties.loopback
            p_router_properties['routerid'] = router_properties.routerid
            p_router_properties['mgmtip'] = mgmtAllocator.nextMgmtAddress()
        self.routers_properties = p_routers_properties
        # Generation of the hosts parameters
        for p_host_properties in p_hosts_properties:
            p_host_properties['mgmtip'] = mgmtAllocator.nextMgmtAddress()
        self.hosts_properties = p_hosts_properties
        # Generation of the controllers parameters
        controllers_properties = generator.getRoutersProperties(self.controllers)
        for controller_properties, p_controller_properties in zip(controllers_properties, p_controllers_properties):
            p_controller_properties['routerid'] = controller_properties.routerid
            p_controller_properties['mgmtip'] = mgmtAllocator.nextMgmtAddress()
        self.controllers_properties = p_controllers_properties
        # Assign mgmt ip to the mgmt station
        self.mgmtIP = mgmtAllocator.nextMgmtAddress()
        # Third step is the generation of the links parameters
        # Generation of the core links parameters
        core_links_properties = []
        for core_link in self.core_links:
            core_links_properties.append(generator.getCoreLinksProperties([core_link]))
        for core_link_properties, p_core_link_properties in zip(core_links_properties, p_core_links_properties):
            p_core_link_properties['iplhs'] = core_link_properties[0].iplhs
            p_core_link_properties['iprhs'] = core_link_properties[0].iprhs
            p_core_link_properties['net'] = core_link_properties[0].net
        self.core_links_properties = p_core_links_properties
        # Generation of the edge links parameters
        edge_links_properties = []
        for edge_link in self.edge_links:
            edge_links_properties.append(generator.getEdgeLinksProperties([edge_link]))
        for edge_link_properties, p_edge_link_properties in zip(edge_links_properties, p_edge_links_properties):
            p_edge_link_properties['iplhs'] = edge_link_properties[0].iplhs
            p_edge_link_properties['iprhs'] = edge_link_properties[0].iprhs
            p_edge_link_properties['net'] = edge_link_properties[0].net
        self.edge_links_properties = p_edge_links_properties
        # Generation of the mgmt links parameters
        mgmt_links_properties = []
        for mgmt_link in self.mgmt_links:
            mgmt_links_properties.append(generator.getLinksProperties([mgmt_link]))
        for mgmt_link_properties, p_mgmt_link_properties in zip(mgmt_links_properties, p_mgmt_links_properties):
            p_mgmt_link_properties['iplhs'] = mgmt_link_properties[0].iplhs
            p_mgmt_link_properties['iprhs'] = mgmt_link_properties[0].iprhs
            p_mgmt_link_properties['net'] = mgmt_link_properties[0].net
        self.mgmt_links_properties = p_mgmt_links_properties
        # Init steps
        Topo.__init__( self, **opts )

    # Build the topology using parser information
    def build( self, *args, **params ):
        # Mapping nodes to nets
        nodes_to_nets = defaultdict(list)
        # Init steps
        Topo.build( self, *args, **params )
        # Add routers
        for router, router_properties in zip(self.routers, self.routers_properties):
            # Assign mgmtip, loobackip, routerid
            mgmtIP = router_properties['mgmtip']
            loopbackIP = router_properties['loopback']
            routerid = router_properties['routerid']
            loopbackip = "%s/%s" % (loopbackIP, LoopbackAllocator.prefix)
            mgmtip = "%s/%s" % (mgmtIP, MgmtAllocator.prefix)
            # Add the router to the topology
            self.addHost(name=router, cls=SRv6Router, sshd=True, mgmtip=mgmtip,
                loopbackip=loopbackip, routerid=routerid, nets=[])
            # Save mapping node to mgmt
            nodes_to_mgmt[router] = str(mgmtIP)
            # Save mapping node to loopbackip
            nodes_to_loopbackip[router] = str(loopbackIP)
            # Add node to the topology graph
            topology.add_node(router, mgmtip=mgmtip , loopbackip=loopbackip,
                routerid=routerid, type="router")
        # Add hosts
        for host, host_properties in zip(self._hosts, self.hosts_properties):
            # Assign mgmtip, loobackip, routerid
            mgmtIP = host_properties['mgmtip']
            mgmtip = "%s/%s" % (mgmtIP, MgmtAllocator.prefix)
            # Add the host to the topology
            self.addHost(name=host, cls=MHost, sshd=True, mgmtip=mgmtip, nets=[])
            # Save mapping node to mgmt
            nodes_to_mgmt[host] = str(mgmtIP)
            # Add node to the topology graph
            topology.add_node(host, mgmtip=mgmtip, type="host")
        # Create the mgmt switch
        br_mgmt = self.addSwitch(name='br-mgmt1', cls=OVSBridge)
        # Add controllers
        for controller, controller_properties in zip(self.controllers, self.controllers_properties):
            # Assign mgmtip, loobackip, routerid
            mgmtIP = controller_properties['mgmtip']
            routerid = controller_properties['routerid']
            mgmtip = "%s/%s" % (mgmtIP, MgmtAllocator.prefix)
            # Add the host to the topology
            self.addHost(name=controller, cls=SRv6Controller, routerid=routerid, sshd=False, mgmtip=mgmtip, nets=[], neighbors=[])
            # Save mapping node to mgmt
            nodes_to_mgmt[controller] = str(mgmtIP)
            # Add node to the topology graph
            topology.add_node(controller, routerid=routerid, mgmtip=mgmtip, type="controller")
            # Create a link between mgmt switch and mgmt station
            self.addLink(controller, br_mgmt, bw=1000, delay=0)
        # Assign the mgmt ip to the mgmt station
        mgmtIP = self.mgmtIP
        mgmtip = "%s/%s" % (mgmtIP, MgmtAllocator.prefix)
        # Mgmt name
        mgmt = 'mgmt'
        # Create the mgmt node in the root namespace
        self.addHost(name=mgmt, cls=SRv6Router, sshd=False, mgmtip=mgmtip,
            inNamespace=False)
        nodes_to_mgmt[mgmt] = str(mgmtIP)
        # Create a link between mgmt switch and mgmt station
        self.addLink(mgmt, br_mgmt, bw=1000, delay=0)
        # Connect all the routers to the management network
        for router in self.routers:
            # Create a link between mgmt switch and the router
            self.addLink(router, br_mgmt, bw=1000, delay=0)
        for host in self._hosts:
            # Create a link between mgmt switch and the host
            self.addLink(host, br_mgmt, bw=1000, delay=0)
        for controller in self.controllers:
            # Create a link between mgmt switch and the host
            self.addLink(controller, br_mgmt, bw=1000, delay=0)
        # Iterate over the core links and generate them
        for core_link, core_link_properties in zip(self.core_links, self.core_links_properties):
            # Get the left hand side of the pair
            lhs = core_link[0]
            # Get the right hand side of the pair
            rhs = core_link[1]
            # Create the core link
            self.addLink(lhs, rhs, bw=core_link_properties['bw'],
                delay=core_link_properties['delay'])
            # Get Port number
            portNumber = self.port(lhs, rhs)
            # Create lhs_intf
            lhsintf = "%s-eth%d" % (lhs, portNumber[0])
            # Create rhs_intf
            rhsintf = "%s-eth%d" % (rhs, portNumber[1])
            # Assign a data-plane net to this link
            net = core_link_properties['net']
            # Get lhs ip
            lhsip = "%s/%d" % (core_link_properties['iplhs'], IPv6NetAllocator.prefix)
            # Get rhs ip
            rhsip = "%s/%d" % (core_link_properties['iprhs'], IPv6NetAllocator.prefix)
            # Add edge to the topology
            topology.add_edge(lhs, rhs, lhs_intf=lhsintf, rhs_intf=rhsintf, lhs_ip=lhsip, rhs_ip=rhsip)
            # Add the reverse edge to the topology
            topology.add_edge(rhs, lhs, lhs_intf=rhsintf, rhs_intf=lhsintf, lhs_ip=rhsip, rhs_ip=lhsip)
            # Save net
            lhsnet = {'intf':lhsintf, 'ip':lhsip, 'net':net, 'stub':False}
            rhsnet = {'intf':rhsintf, 'ip':rhsip, 'net':net, 'stub':False}
            self.nodeInfo(lhs)['nets'].append(lhsnet)
            self.nodeInfo(rhs)['nets'].append(rhsnet)
        # Iterate over the edge links and generate them
        for edge_link, edge_link_properties in zip(self.edge_links, self.edge_links_properties):
            # Get the left hand side of the pair
            lhs = edge_link[0]
            # Get the right hand side of the pair
            rhs = edge_link[1]
            # Create the edge link
            self.addLink(lhs, rhs, bw=edge_link_properties['bw'],
                delay=edge_link_properties['delay'])
            # Get Port number
            portNumber = self.port(lhs, rhs)
            # Create lhs_intf
            lhsintf = "%s-eth%d" % (lhs, portNumber[0])
            # Create rhs_intf
            rhsintf = "%s-eth%d" % (rhs, portNumber[1])
            # Assign a data-plane net to this link
            net = edge_link_properties['net']
            # Get lhs ip
            if srv6_utils.IPv6_EMULATION:
                lhsip = "%s/%d" % (edge_link_properties['iplhs'], IPv6NetAllocator.prefix)
            else:
                lhsip = "%s/%d" % (edge_link_properties['iplhs'], IPv4NetAllocator.prefix)
            # Get rhs ip
            if srv6_utils.IPv6_EMULATION:
                rhsip = "%s/%d" % (edge_link_properties['iprhs'], IPv6NetAllocator.prefix)
            else:
                rhsip = "%s/%d" % (edge_link_properties['iprhs'], IPv4NetAllocator.prefix)
            # Add edge to the topology
            topology.add_edge(lhs, rhs, lhs_intf=lhsintf, rhs_intf=rhsintf, lhs_ip=lhsip, rhs_ip=rhsip)
            # Add the reverse edge to the topology
            topology.add_edge(rhs, lhs, lhs_intf=rhsintf, rhs_intf=lhsintf, lhs_ip=rhsip, rhs_ip=lhsip)
            # Save net
            # Mark the nets as stub in order to set them
            # as passive interfaces in the OSPF configuration
            lhsnet = {'intf':lhsintf, 'ip':lhsip, 'net':net, 'stub':True}
            rhsnet = {'intf':rhsintf, 'ip':rhsip, 'net':net, 'stub':True}
            self.nodeInfo(lhs)['nets'].append(lhsnet)
            self.nodeInfo(rhs)['nets'].append(rhsnet)
        # Iterate over the mgmt links and generate them
        for mgmt_link, mgmt_link_properties in zip(self.mgmt_links, self.mgmt_links_properties):
            # Get the left hand side of the pair
            lhs = mgmt_link[0]
            # Get the right hand side of the pair
            rhs = mgmt_link[1]
            # Create the mgmt link
            self.addLink(lhs, rhs, bw=mgmt_link_properties['bw'],
                delay=mgmt_link_properties['delay'])
            # Get Port number
            portNumber = self.port(lhs, rhs)
            # Create lhs_intf
            lhsintf = "%s-eth%d" % (lhs, portNumber[0])
            # Create rhs_intf
            rhsintf = "%s-eth%d" % (rhs, portNumber[1])
            # Assign a data-plane net to this link
            net = mgmt_link_properties['net']
            # Get lhs ip
            lhsip = "%s/%d" % (mgmt_link_properties['iplhs'], NetAllocator.prefix)
            # Get rhs ip
            rhsip = "%s/%d" % (mgmt_link_properties['iprhs'], NetAllocator.prefix)
            # Add edge to the topology
            topology.add_edge(lhs, rhs, lhs_intf=lhsintf, rhs_intf=rhsintf, lhs_ip=lhsip, rhs_ip=rhsip)
            # Add the reverse edge to the topology
            topology.add_edge(rhs, lhs, lhs_intf=rhsintf, rhs_intf=lhsintf, lhs_ip=rhsip, rhs_ip=lhsip)
            # Save net
            # Mark the nets as stub in order to set them
            # as passive interfaces in the OSPF configuration
            lhsnet = {'intf':lhsintf, 'ip':lhsip, 'net':net, 'stub':False, 'mgmt': True}
            rhsnet = {'intf':rhsintf, 'ip':rhsip, 'net':net, 'stub':False, 'mgmt': True}
            self.nodeInfo(lhs)['nets'].append(lhsnet)
            self.nodeInfo(rhs)['nets'].append(rhsnet)
            if lhs in self.controllers:
                self.nodeInfo(lhs)['neighbors'].append(nodes_to_loopbackip[rhs])
            elif rhs in self.controllers:
                self.nodeInfo(rhs)['neighbors'].append(nodes_to_loopbackip[lhs])

        
# Utility function to dump relevant information of the emulation
def dump():
  # Json dump of the topology
  with open(TOPOLOGY_FILE, 'w') as outfile:
    # Get json topology
    json_topology = json_graph.node_link_data(topology)
    # Convert links
    json_topology['links'] = [
        {
            'source': link['source'],
            'target': link['target'],
            'lhs_intf': link['lhs_intf'],
            'rhs_intf': link['rhs_intf'],
            'lhs_ip': str((ipaddress.ip_interface(link['lhs_ip'])).ip),
            'rhs_ip': str((ipaddress.ip_interface(link['rhs_ip'])).ip)
        }
        for link in json_topology['links']]
    # Dump the topology
    json.dump(json_topology, outfile, sort_keys = True, indent = 2)
  # Dump for nodes.sh
  with open(NODES_SH, 'w') as outfile:
    # Create header
    nodes = "declare -a NODES=("
    # Iterate over management ips
    for node, ip in nodes_to_mgmt.iteritems():
      # Add the nodes one by one
      nodes = nodes + "%s " % ip
    if nodes_to_mgmt != {}:
        # Eliminate last character
        nodes = nodes[:-1] + ")\n"
    else:
        nodes = nodes + ")\n"
    # Write on the file
    outfile.write(nodes)

# Utility function to shutdown the emulation
def stopAll():
    # Clean Mininet emulation environment
    os.system('sudo mn -c')
    # Kill all the started daemons
    os.system('sudo killall sshd zebra ospf6d')
    # Restart root ssh daemon
    os.system('service sshd restart')

# Utility function to deploy Mininet topology
def deploy( options ):
    # Retrieves options
    controller = options.controller
    topologyFile = options.topology
    clean_all = options.clean_all
    no_cli = options.no_cli
    srv6_utils.IPv6_EMULATION = options.ipv6_emulation
    # Clean all - clean and exit
    if clean_all:
        stopAll()
        return
    # Set Mininet log level to info
    setLogLevel('info')
    # Create Mininet topology
    topo = SRv6Topo(topo=topologyFile)
    # Create Mininet net
    net = Mininet(topo=topo, link=TCLink,
        build=False, controller=None)
    # Add manually external controller
    net.addController("c0", controller=RemoteController, ip=controller)
    # Build topology
    net.build()
    # Start topology
    net.start()
    # dump information
    dump()
    # Show Mininet prompt
    if not no_cli:
        # Mininet CLI
        CLI(net)
        # Stop topology
        net.stop()
        # Clean all
        stopAll()

# Parse command line options and dump results
def parseOptions():
    parser = OptionParser()
    # IP of RYU controller
    parser.add_option('--controller', dest='controller', type='string', default="127.0.0.1",
                      help='IP address of the Controlle instance')
    # Topology json file
    parser.add_option('--topology', dest='topology', type='string', default="example_srv6_topology.json",
                      help='Topology file')
    # Enable IPv6 emulation
    parser.add_option('--ipv6', dest='ipv6_emulation', action='store_true', default=False,
                      help='Enable IPv6 emulation')
    # Clean all useful for rdcl stop action
    parser.add_option('--stop-all', dest='clean_all',action='store_true', help='Clean all mininet environment')
    # Start without Mininet prompt - useful for rdcl start action
    parser.add_option('--no-cli', dest='no_cli',action='store_true', help='Do not show Mininet CLI')
    # Parse input parameters
    (options, args) = parser.parse_args()
    # Done, return
    return options

if __name__ == '__main__':
    # Let's parse input parameters
    opts = parseOptions()
    # Deploy topology
    deploy(opts)
