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


from __future__ import print_function

# General imports
from optparse import OptionParser
import os
import json
# Mininet dependencies
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController, OVSBridge
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import error
# ipaddress dependencies
from ipaddress import IPv6Network, IPv4Network
# NetworkX dependencies
import networkx as nx
from networkx.readwrite import json_graph
# SRv6 dependencies
from srv6_topo_parser import SRv6TopoParser
from srv6_utils import SRv6Router, MHost, SRv6Controller, WANRouter
from srv6_generators import IPv6PropertiesGenerator, IPv4PropertiesGenerator
from srv6_generators import LoopbackAllocator
from srv6_generators import IPv6NetAllocator, IPv4NetAllocator
#from srv6_generators import IPv6MgmtAllocator

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
    def __init__(self, topo="", out_of_band_controller=False,
                 wan_router_private_addr=False, wan_router_script=None,
                 use_ipv4_addressing=False, debug=False, **opts):
        # Arguments
        self.out_of_band_controller = out_of_band_controller
        self.wan_router_private_addr = wan_router_private_addr
        self.wan_router_script = wan_router_script
        self.use_ipv4_addressing = use_ipv4_addressing
        self.debug = debug
        # Parse topology from json file
        parser = SRv6TopoParser(topo, verbose=False)
        parser.parse_data()
        # Stub links
        self.stub_links = list()
        # Private links
        self.private_links = list()
        # Save parsed data
        self.routers = parser.getRouters()
        p_routers_properties = parser.getRoutersProperties()
        self._hosts = parser.getHosts()
        p_hosts_properties = parser.getHostsProperties()
        # Identify ospf routers and default routes
        self.ospf_routers = list()
        self.default_vias = dict()
        for router, p_router_properties in zip(self.routers, p_routers_properties):
            if p_router_properties.get('enable_ospf', False):
                self.ospf_routers.append(router)
            self.default_vias[router] = p_router_properties.get('default_via', None)
        # Identify the controller
        self.controller = None
        for host, p_host_properties in zip(self._hosts, p_hosts_properties):
            if p_host_properties.get('is_controller') is True:
                if self.controller is not None:
                    error('Error: Multi-controller topologies are not supported')
                    exit(-1)
                self.controller = host
            self.default_vias[host] = p_host_properties.get('default_via', None)
        # Add the WAN router to the hosts
        self.wan_router = 'wanrouter'
        self._hosts.append(self.wan_router)
        p_hosts_properties.append({'is_wan_router': True})
        # Process links
        self.core_links = parser.getCoreLinks()
        p_core_links_properties = parser.getCoreLinksProperties()
        self.edge_links = parser.getEdgeLinks()
        p_edge_links_properties = parser.getEdgeLinksProperties()
        # Add controller-WAN router link
        if self.wan_router is not None and self.controller is not None:
            self.edge_links.append((self.controller, self.wan_router))
            p_edge_links_properties.append({'bw': 1000, 'delay': 0})
        # Properties generator
        if self.use_ipv4_addressing:
            generator = IPv4PropertiesGenerator()
            self.netprefix = IPv4NetAllocator.prefix
        else:
            generator = IPv6PropertiesGenerator()
            self.netprefix = IPv6NetAllocator.prefix
        # Second step is the generation of the nodes parameters
        # Generation of the routers parameters
        routers_properties = generator.getRoutersProperties(self.routers)
        for (router_properties,
             p_router_properties) in zip(routers_properties,
                                         p_routers_properties):
            p_router_properties['loopback'] = router_properties.loopback
            p_router_properties['routerid'] = router_properties.routerid
            p_router_properties['routernet'] = router_properties.routernet
        self.routers_properties = p_routers_properties
        # Generation of the hosts parameters
        hosts_properties = generator.getHostsProperties(self._hosts)
        for (host_properties,
             p_host_properties) in zip(hosts_properties,
                                       p_hosts_properties):
            p_host_properties['loopback'] = host_properties.loopback
        self.hosts_properties = p_hosts_properties
        # Third step is the generation of the links parameters
        # Generation of the core links parameters
        core_links_properties = []
        for (core_link,
             p_core_link_properties) in zip(self.core_links,
                                            p_core_links_properties):
            core_link = (core_link[0], core_link[1])
            type = p_core_link_properties.get('type', 'core')
            if type == 'core':
                core_links_properties.append(generator
                                             .getCoreLinksProperties([core_link]))
            elif type == 'edge':
                core_links_properties.append(generator
                                             .getEdgeLinksProperties([core_link]))
            elif type == 'access':
                core_links_properties.append(generator
                                             .getAccessLinksProperties([core_link]))
            if p_core_link_properties.get('is_stub', False):
                self.stub_links.append(core_link)
            if p_core_link_properties.get('is_private', False):
                self.private_links.append(core_link)
        for (core_link_properties,
             p_core_link_properties) in zip(core_links_properties,
                                            p_core_links_properties):
            p_core_link_properties['iplhs'] = core_link_properties[0].iplhs
            p_core_link_properties['iprhs'] = core_link_properties[0].iprhs
            p_core_link_properties['net'] = core_link_properties[0].net
            p_core_link_properties['prefix'] = core_link_properties[0].prefix
        self.core_links_properties = p_core_links_properties
        # Generation of the edge links parameters
        edge_links_properties = []
        for (edge_link,
             p_edge_link_properties) in zip(self.edge_links,
                                            p_edge_links_properties):
            edge_link = (edge_link[0], edge_link[1])
            # We treat controller-device links as core links
            if edge_link[0] == self.controller or edge_link[1] == self.controller:
                edge_links_properties.append(generator
                                             .getCoreLinksProperties([edge_link]))
            else:
                type = p_edge_link_properties.get('type', 'edge')
                if type == 'core':
                    edge_links_properties.append(generator
                                                 .getCoreLinksProperties([edge_link]))
                elif type == 'edge':
                    edge_links_properties.append(generator
                                                 .getEdgeLinksProperties([edge_link]))
                elif type == 'access':
                    edge_links_properties.append(generator
                                                 .getAccessLinksProperties([edge_link]))
            # Stub links identification
            if p_edge_link_properties.get('is_stub', False):
                self.stub_links.append(edge_link)
            # Private links identification
            if p_edge_link_properties.get('is_private', False):
                self.private_links.append(edge_link)
        for (edge_link_properties,
             p_edge_link_properties) in zip(edge_links_properties,
                                            p_edge_links_properties):
            p_edge_link_properties['iplhs'] = edge_link_properties[0].iplhs
            p_edge_link_properties['iprhs'] = edge_link_properties[0].iprhs
            p_edge_link_properties['net'] = edge_link_properties[0].net
            p_edge_link_properties['prefix'] = edge_link_properties[0].prefix
        self.edge_links_properties = p_edge_links_properties
        '''
        for (edge_link,
             p_edge_link_properties) in zip(self.edge_links,
                                            p_edge_links_properties):
            edge_link = (edge_link[0], edge_link[1])
            if p_edge_link_properties.get('is_stub', False):
                self.stub_links.append(edge_link)
            if p_edge_link_properties.get('is_private', False):
                self.private_links.append(edge_link)
        for (core_link,
             p_core_link_properties) in zip(self.core_links,
                                            p_core_links_properties):
            core_link = (core_link[0], core_link[1])
            if p_core_link_properties.get('is_private', False):
                self.private_links.append(core_link)
        '''
        # Init steps
        Topo.__init__(self, **opts)


    # Build the topology using parser information
    def build(self, *args, **params):
        self.wan_router = None
        self.vias = dict()
        # Init steps
        Topo.build(self, *args, **params)
        # Add routers
        for router, router_properties in zip(self.routers,
                                             self.routers_properties):
            # Assign mgmtip, loobackip, routerid
            #mgmtIP = router_properties['mgmtip']
            loopbackIP = router_properties['loopback']
            routerid = router_properties['routerid']
            routernet = router_properties['routernet']
            if loopbackIP is None:
                loopbackip = None
            else:
                loopbackip = "%s/%s" % (loopbackIP, LoopbackAllocator.prefix)
            #mgmtip = "%s/%s" % (mgmtIP, IPv6MgmtAllocator.prefix)
            # Enable ospfd?
            enable_ospf = router in self.ospf_routers
            # Add the router to the topology
            self.addHost(name=router, cls=SRv6Router, sshd=True,
                         loopbackip=loopbackip, routerid=routerid,
                         routernet=routernet, use_ipv4_addressing=self.use_ipv4_addressing,
                         nets=[], routes=[], enable_ospf=enable_ospf, debug=self.debug)
            # Save mapping node to mgmt
            #nodes_to_mgmt[router] = str(mgmtIP)
            # Save mapping node to loopbackip
            nodes_to_loopbackip[router] = str(loopbackIP)
            # Add node to the topology graph
            topology.add_node(router, loopbackip=loopbackip,
                              routerid=routerid, type="router")
        # Add hosts
        for host, host_properties in zip(self._hosts, self.hosts_properties):
            # Assign mgmtip, loobackip, routerid
            is_controller = host_properties.get('is_controller', False)
            is_wan_router = host_properties.get('is_wan_router', False)
            #mgmtIP = host_properties['mgmtip']
            loopbackIP = router_properties['loopback']
            if loopbackIP is None:
                loopbackip = None
            else:
                loopbackip = "%s/%s" % (loopbackIP, LoopbackAllocator.prefix)
            #mgmtip = "%s/%s" % (mgmtIP, IPv6MgmtAllocator.prefix)
            if is_controller:
                # Add the controller to the topology
                self.addHost(name=host, cls=SRv6Controller, sshd=True, in_band=True,
                             loopbackip=loopbackip, nets=[], routes=[], debug=self.debug)
                # Add node to the topology graph
                topology.add_node(host, loopbackip=loopbackip, type="controller")
                # Save controller loopback IP
                self.controller_loopbackip = loopbackip
            elif is_wan_router:
                if self.wan_router is not None:
                    error('Error: only a WAN router is supported')
                    exit(-1)
                self.wan_router = host
                # Add the WAN router to the topology
                self.addHost(name=host, cls=WANRouter, sshd=True,
                             wan_router_script=self.wan_router_script,
                             loopbackip=loopbackip, nets=[], routes=[], debug=self.debug)
                # Add node to the topology graph
                topology.add_node(host, loopbackip=loopbackip, type="controller")
            else:
                # Add the host to the topology
                self.addHost(name=host, cls=MHost, sshd=True,
                             loopbackip=loopbackip, nets=[], routes=[],
                             debug=self.debug)
                # Add node to the topology graph
                topology.add_node(host, loopbackip=loopbackip, type="host")
        # Configure the controller and the WAN router
        if self.out_of_band_controller:
            if self.use_ipv4_addressing:
                nets = IPv4Network(u'172.0.0.0/16')
                nets = nets.subnets(new_prefix=30)
                controller_loopbackip = None
            else:
                nets = IPv6Network(u'2000::/16')
                nets = nets.subnets(new_prefix=64)
                controller_loopbackip = u'fcff::1/32'
            # Add the controller to the topology
            self.controller = 'controller'
            self.addHost(name=self.controller, cls=SRv6Controller, sshd=False,
                         inNamespace=False, in_band=False, nets=[], debug=self.debug)
            # Add the WAN router to the topology
            self.wan_router = 'wanrouter'
            # Assign a data-plane net to this link
            if self.wan_router_private_addr:
                if self.use_ipv4_addressing:
                    net = IPv4Network(u'172.0.0.0/16')
                else:
                    net = IPv6Network(u'2002::/16')
                hosts = net.hosts()
                # Get lhs ip
                lhsip = next(hosts).__str__()
                # Get rhs ip
                rhsip = next(hosts).__str__()
            else:
                net = next(nets)
                hosts = net.hosts()
                # Get lhs ip
                lhsip = next(hosts).__str__()
                # Get rhs ip
                rhsip = next(hosts).__str__()
                net = net.__str__()
            controller_wan_router_net = net
            # Create a link between controller and WAN router
            self.addLink(self.controller, self.wan_router, bw=1000, delay=0)
            # Get Port number
            portNumber = self.port(self.controller, self.wan_router)
            # Create lhs_intf
            lhsintf = "%s-eth%d" % (self.controller, portNumber[0])
            # Create rhs_intf
            rhsintf = "%s-eth%d" % (self.wan_router, portNumber[1])
            # Configure the default via of the controller and the WAN router
            self.nodeInfo(self.controller)['default_via'] = rhsip
            if controller_loopbackip is not None:
                self.nodeInfo(self.wan_router)['routes'].append({'dest': controller_loopbackip, 'via': lhsip})
            # Save net
            lhsip = '%s/%s' % (lhsip, self.netprefix)
            rhsip = '%s/%s' % (rhsip, self.netprefix)
            lhsnet = {'intf': lhsintf, 'ip': lhsip, 'net': net, 'bw': 1000, 'stub': False, 'is_private': True}
            rhsnet = {'intf': rhsintf, 'ip': rhsip, 'net': net, 'bw': 1000, 'stub': False, 'is_private': True}
            self.nodeInfo(self.controller)['nets'].append(lhsnet)
            self.nodeInfo(self.wan_router)['nets'].append(rhsnet)
            # Connect all the routers to the management network
            for router in self.routers:
                # Assign a data-plane net to this link
                net = next(nets)
                hosts = net.hosts()
                # Get lhs ip
                lhsip = next(hosts).__str__()
                # Get rhs ip
                rhsip = next(hosts).__str__()
                # Create a link between the WAN router and the router
                self.addLink(router, self.wan_router, bw=1000, delay=0)
                # Get Port number
                portNumber = self.port(router, self.wan_router)
                # Create lhs_intf
                lhsintf = "%s-eth%d" % (router, portNumber[0])
                # Create rhs_intf
                rhsintf = "%s-eth%d" % (self.wan_router, portNumber[1])
                # Add the route to the router
                if controller_loopbackip is not None:
                    self.nodeInfo(router)['routes'].append({'dest': controller_loopbackip, 'via': rhsip})
                self.nodeInfo(router)['routes'].append({'dest': controller_wan_router_net, 'via': rhsip})
                # Save net
                lhsip = '%s/%s' % (lhsip, self.netprefix)
                rhsip = '%s/%s' % (rhsip, self.netprefix)
                lhsnet = {'intf': lhsintf, 'ip': lhsip, 'net': net, 'bw': 1000, 'stub': False, 'is_private': True}
                rhsnet = {'intf': rhsintf, 'ip': rhsip, 'net': net, 'bw': 1000, 'stub': False, 'is_private': True}
                self.nodeInfo(router)['nets'].append(lhsnet)
                self.nodeInfo(self.wan_router)['nets'].append(rhsnet)
            # Connect all the hosts to the management network
            for host in self._hosts:
                if host == self.wan_router:
                    # Skip
                    continue
                if host == self.controller:
                    # Skip
                    continue
                # Assign a data-plane net to this link
                net = next(nets)
                hosts = net.hosts()
                # Get lhs ip
                lhsip = next(hosts).__str__()
                # Get rhs ip
                rhsip = next(hosts).__str__()
                # Create a link between the WAN router and the router
                self.addLink(host, self.wan_router, bw=1000, delay=0)
                # Get Port number
                portNumber = self.port(host, self.wan_router)
                # Create lhs_intf
                lhsintf = "%s-eth%d" % (host, portNumber[0])
                # Create rhs_intf
                rhsintf = "%s-eth%d" % (self.wan_router, portNumber[1])
                # Add the route to the router
                if controller_loopbackip is not None:
                    self.nodeInfo(host)['routes'].append({'dest': controller_loopbackip, 'via': rhsip})
                self.nodeInfo(host)['routes'].append({'dest': controller_wan_router_net, 'via': rhsip})
                # Save net
                lhsip = '%s/%s' % (lhsip, self.netprefix)
                rhsip = '%s/%s' % (rhsip, self.netprefix)
                lhsnet = {'intf': lhsintf, 'ip': lhsip, 'net': net, 'bw': 1000, 'stub': False, 'is_private': True}
                rhsnet = {'intf': rhsintf, 'ip': rhsip, 'net': net, 'bw': 1000, 'stub': False, 'is_private': True}
                self.nodeInfo(host)['nets'].append(lhsnet)
                self.nodeInfo(self.wan_router)['nets'].append(rhsnet)
        # Iterate over the core links and generate them
        for core_link, core_link_properties in zip(self.core_links,
                                                   self.core_links_properties):
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
            # Prefix
            prefix = core_link_properties['prefix']
            # Get lhs ip
            lhsip = "%s/%d" % (core_link_properties['iplhs'],
                               prefix)
            # Get rhs ip
            rhsip = "%s/%d" % (core_link_properties['iprhs'],
                               prefix)
            # Add edge to the topology
            topology.add_edge(lhs, rhs, lhs_intf=lhsintf,
                              rhs_intf=rhsintf, lhs_ip=lhsip, rhs_ip=rhsip)
            # Add the reverse edge to the topology
            topology.add_edge(rhs, lhs, lhs_intf=rhsintf,
                              rhs_intf=lhsintf, lhs_ip=rhsip, rhs_ip=lhsip)
            # Configure the cost of the nets
            cost = core_link_properties.get('cost')
            is_stub = (lhs, rhs) in self.stub_links
            is_private = (lhs, rhs) in self.private_links
            # Save net
            lhsnet = {'intf': lhsintf, 'ip': lhsip, 'net': net, 'cost': cost, 'bw': core_link_properties['bw'], 'stub': is_stub, 'is_private': is_private}
            rhsnet = {'intf': rhsintf, 'ip': rhsip, 'net': net, 'cost': cost, 'bw': core_link_properties['bw'], 'stub': is_stub, 'is_private': is_private}
            self.nodeInfo(lhs)['nets'].append(lhsnet)
            self.nodeInfo(rhs)['nets'].append(rhsnet)
            # Default via
            default_via = self.default_vias.get(lhs, None)
            if default_via is not None and default_via == rhs:
                self.nodeInfo(lhs)['default_via'] = core_link_properties['iprhs']
            default_via = self.default_vias.get(rhs, None)
            if default_via is not None and default_via == lhs:
                self.nodeInfo(rhs)['default_via'] = core_link_properties['iplhs']
        # Iterate over the edge links and generate them
        for edge_link, edge_link_properties in zip(self.edge_links,
                                                   self.edge_links_properties):
            # Get the left hand side of the pair
            lhs = edge_link[0]
            # Get the right hand side of the pair
            rhs = edge_link[1]
            # Connect the routers to the WAN router instead of controller
            if lhs == self.controller and rhs in self.routers:
                lhs = self.wan_router
            elif lhs in self.routers and rhs == self.controller:
                rhs = self.wan_router
            # Create the edge link
            self.addLink(lhs, rhs, bw=edge_link_properties['bw'],
                         delay=edge_link_properties['delay'])
            # Get Port number
            portNumber = self.port(lhs, rhs)
            # Create lhs_intf
            lhsintf = "%s-eth%d" % (lhs, portNumber[0])
            # Create rhs_intf
            rhsintf = "%s-eth%d" % (rhs, portNumber[1])
            # Use private addresses
            if lhs == self.controller and rhs == self.wan_router:
                # Assign a data-plane net to this link
                net = edge_link_properties['net']
                # Get lhs ip
                lhsip = edge_link_properties['iplhs']
                # Get rhs ip
                rhsip = edge_link_properties['iprhs']
                # Prefix
                prefix = edge_link_properties['prefix']
                net = net.__str__()
                if self.wan_router_private_addr:
                    net = IPv6Network(u'fcfa::/16')
                    hosts = net.hosts()
                    # Get lhs ip
                    lhsip = next(hosts).__str__()
                    # Get rhs ip
                    rhsip = next(hosts).__str__()
                    net = net.__str__()
                self.controller_wan_router_net = net
            else:
                # Assign a data-plane net to this link
                net = edge_link_properties['net']
                # Get lhs ip
                lhsip = edge_link_properties['iplhs']
                # Get rhs ip
                rhsip = edge_link_properties['iprhs']
                # Prefix
                prefix = edge_link_properties['prefix']
                net = net.__str__()
            # Configure the default via of the controller and the WAN router
            if lhs == self.controller and rhs == self.wan_router:
                self.nodeInfo(self.controller)['default_via'] = rhsip
                if self.controller_loopbackip is not None:
                    self.nodeInfo(self.wan_router)['routes'].append({'dest': self.controller_loopbackip, 'via': lhsip})
            elif lhs == self.wan_router:
                self.nodeInfo(self.wan_router)['default_via'] = rhsip
            elif rhs == self.wan_router:
                self.nodeInfo(self.wan_router)['default_via'] = lhsip
            # Add the route to the router
            if lhs in self.routers and rhs == self.wan_router:
                self.vias[lhs] = rhsip
            if rhs in self.routers and lhs == self.wan_router:
                self.vias[rhs] = lhsip
            lhsip = '%s/%s' % (lhsip, prefix)
            rhsip = '%s/%s' % (rhsip, prefix)
            # Add edge to the topology
            topology.add_edge(lhs, rhs, lhs_intf=lhsintf,
                              rhs_intf=rhsintf, lhs_ip=lhsip, rhs_ip=rhsip)
            # Add the reverse edge to the topology
            topology.add_edge(rhs, lhs, lhs_intf=rhsintf,
                              rhs_intf=lhsintf, lhs_ip=rhsip, rhs_ip=lhsip)
            # Configure the cost of the nets
            cost = edge_link_properties.get('cost')
            # Save net
            # Mark the nets as stub in order to set them
            # as passive interfaces in the OSPF configuration
            is_stub = (lhs, rhs) in self.stub_links
            lhsnet = {'intf': lhsintf, 'ip': lhsip, 'net': net, 'cost': cost, 'bw': edge_link_properties['bw'], 'stub': is_stub, 'is_private': is_private}
            rhsnet = {'intf': rhsintf, 'ip': rhsip, 'net': net, 'cost': cost, 'bw': edge_link_properties['bw'], 'stub': is_stub, 'is_private': is_private}
            self.nodeInfo(lhs)['nets'].append(lhsnet)
            self.nodeInfo(rhs)['nets'].append(rhsnet)
            # Default via
            default_via = self.default_vias.get(lhs, None)
            if default_via is not None and default_via == rhs:
                self.nodeInfo(lhs)['default_via'] = edge_link_properties['iprhs']
            default_via = self.default_vias.get(rhs, None)
            if default_via is not None and default_via == lhs:
                self.nodeInfo(rhs)['default_via'] = edge_link_properties['iplhs']
        # Add routes to reach the controller to the routers
        for router in self.vias:
            if self.controller_loopbackip is not None:
                self.nodeInfo(router)['routes'].append({'dest': self.controller_loopbackip, 'via': self.vias[router]})
            self.nodeInfo(router)['routes'].append({'dest': self.controller_wan_router_net, 'via': self.vias[router]})


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
                'lhs_ip': link['lhs_ip'],
                'rhs_ip': link['rhs_ip']
            }
            for link in json_topology['links']]
        # Dump the topology
        json.dump(json_topology, outfile, sort_keys=True, indent=2)
    # Dump for nodes.sh
    with open(NODES_SH, 'w') as outfile:
        # Create header
        nodes = "declare -a NODES=("
        # Iterate over management ips
        for node, ip in nodes_to_mgmt.items():
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
    os.system('sudo killall sshd zebra ospf6d ospfd')
    # Restart root ssh daemon
    os.system('service sshd restart')


# Utility function to deploy Mininet topology
def deploy(options):
    # Retrieves options
    debug = options.debug
    topologyFile = options.topology
    clean_all = options.clean_all
    no_cli = options.no_cli
    wan_router_private_addr = options.wan_router_private_addr
    ipv4_addressing = options.ipv4_addressing
    #firewall_type = options.firewall
    out_of_band_controller = options.out_of_band_controller
    # Clean all - clean and exit
    if clean_all:
        stopAll()
        return
    # Set Mininet log level to info
    setLogLevel('info')
    # Create Mininet topology
    topo = SRv6Topo(topo=topologyFile,
                    out_of_band_controller=out_of_band_controller,
                    wan_router_private_addr=wan_router_private_addr,
                    use_ipv4_addressing=ipv4_addressing,
                    debug=debug)
    # Create Mininet net
    net = Mininet(topo=topo, link=TCLink, build=False, controller=None)
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
    # Debug mode
    parser.add_option('-d', '--debug', dest='debug', action='store_true',
                      default=False, help='Enable debug mode')
    # Topology json file
    parser.add_option('--topology', dest='topology', type='string',
                      default="example_srv6_topology.json",
                      help='Topology file')
    # Clean all useful for rdcl stop action
    parser.add_option('--stop-all', dest='clean_all', action='store_true',
                      help='Clean all mininet environment')
    # Start without Mininet prompt - useful for rdcl start action
    parser.add_option('--no-cli', dest='no_cli', action='store_true',
                      help='Do not show Mininet CLI')
    # Use IPv4 addressing
    parser.add_option('--ipv4', dest='ipv4_addressing', default=False,
                      action='store_true', help='Use IPv4 addressing')
    # Add a out of band controller to the topology
    parser.add_option('--controller', dest='out_of_band_controller',
                      default=False, action='store_true',
                      help='Add a out of band controller to the topology')
    # Use private addresses for the link controller - WAN router
    parser.add_option('--wan_router_private_addr', dest='wan_router_private_addr',
                      default=False, action='store_true',
                      help='Use private addresses for the link controller - WAN router')
    # Parse input parameters
    (options, args) = parser.parse_args()
    # Done, return
    return options


if __name__ == '__main__':
    # Let's parse input parameters
    opts = parseOptions()
    # Deploy topology
    deploy(opts)
