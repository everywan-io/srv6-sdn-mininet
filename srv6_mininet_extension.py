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


from __future__ import absolute_import, division, print_function

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
# Mapping node to interface addresses
nodes_to_ips = {}
# Network topology
topology = nx.MultiDiGraph()


# Create SRv6 topology and a management network for the hosts.
class SRv6Topo(Topo):

    # Init of the topology
    def __init__(self, topo="",
                 use_ipv4_addressing=False, debug=False, **opts):
        # Arguments
        self.use_ipv4_addressing = use_ipv4_addressing
        self.debug = debug
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
        # Properties generator
        if self.use_ipv4_addressing:
            generator = IPv4PropertiesGenerator()
            self.netprefix = IPv4NetAllocator.prefix
            self._net = generator.netAllocator.net
            self.customer_facing_net = generator.customerFacingNetAllocator.net
            self.access_net = generator.accessNetAllocator.net
            self.mgmtNet = generator.mgmtNetAllocator.net
        else:
            generator = IPv6PropertiesGenerator()
            self.netprefix = IPv6NetAllocator.prefix
            self._net = generator.netAllocator.net
            self.customer_facing_net = generator.customerFacingNetAllocator.net
            self.access_net = generator.accessNetAllocator.net
            self.mgmtNet = generator.mgmtNetAllocator.net
        # Identify ospf routers and default routes
        self.ospf_routers = list()
        self.default_vias = dict()
        for router, p_router_properties in zip(self.routers, p_routers_properties):
            if p_router_properties.get('enable_ospf', False):
                self.ospf_routers.append(router)
            self.default_vias[router] = p_router_properties.get(
                'default_via', None)
        # Identify default via for the hosts
        for host, p_host_properties in zip(self._hosts, p_hosts_properties):
            self.default_vias[host] = p_host_properties.get(
                'default_via', None)
        # Process links
        self.core_links = parser.getCoreLinks()
        p_core_links_properties = parser.getCoreLinksProperties()
        self.edge_links = parser.getEdgeLinks()
        p_edge_links_properties = parser.getEdgeLinksProperties()
        self.mgmt_links = parser.getMgmtLinks()
        p_mgmt_links_properties = parser.getMgmtLinksProperties()
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
        # Identify the controller
        if len(self.controllers) == 0:
            self.controller = None
            self.outband_emulation = False
        elif len(self.controllers) == 1:
            self.controller = self.controllers[0]
            self.outband_emulation = p_controllers_properties[0].get(
                'outband', False)
        if len(self.controllers) > 1:
            error('Error: Multi-controller topologies are not supported')
            exit(-1)
        # Identify the WAN router, if there is a controller in the topology
        self.wan_router = None
        if self.controller is not None:
            wan_router = None
            for router, p_router_properties in zip(self.routers, p_routers_properties):
                # Look for the WAN router
                if p_router_properties.get('type') == 'WANRouter':
                    if wan_router is not None:
                        error('Error: Multi-controller topologies are not supported')
                        exit(-1)
                    wan_router = router
                    self.routers.remove(router)
                    p_routers_properties.remove(p_router_properties)
                    p_wanrouter_properties = p_router_properties
            # If no WAN router has been specified in the topology,
            # create a new one
            if wan_router is not None:
                self.wan_router = wan_router
                wanrouters_properties = generator.getHostsProperties(
                    [self.wan_router])
            else:
                self.wan_router = 'wanrouter'
                wanrouters_properties = generator.getHostsProperties(
                    [self.wan_router])
                p_wanrouter_properties = dict()
            p_wanrouter_properties['loopback'] = wanrouters_properties[0].loopback
            self.wanrouter_properties = p_wanrouter_properties
        # Generation of the controllers parameters
        controllers_properties = generator.getHostsProperties(self.controllers)
        for (controller_properties,
             p_controller_properties) in zip(controllers_properties,
                                             p_controllers_properties):
            if not self.outband_emulation:
                p_controller_properties['loopback'] = controller_properties.loopback
        if len(p_controllers_properties) > 0:
            self.controller_properties = p_controllers_properties[0]
        else:
            self.controller_properties = None
        # Third step is the generation of the links parameters
        self._links = self.core_links + self.edge_links + self.mgmt_links
        p_links_properties = p_core_links_properties + \
            p_edge_links_properties + p_mgmt_links_properties
        # Generation of the links parameters
        self.stub_links = list()
        self.private_links = list()
        links_properties = []
        for (link, p_link_properties) in zip(self._links,
                                             p_links_properties):
            link = (link[0], link[1])
            type = p_link_properties.get('type', None)
            if type == 'core':
                links_properties.append(generator
                                        .getCoreLinksProperties([link]))
            elif type == 'edge':
                links_properties.append(generator
                                        .getEdgeLinksProperties([link]))
            elif type == 'access':
                links_properties.append(generator
                                        .getAccessLinksProperties([link]))
            else:
                if link in self.core_links or link in self.mgmt_links:
                    links_properties.append(generator
                                            .getCoreLinksProperties([link]))
                elif link in self.edge_links:
                    links_properties.append(generator
                                            .getEdgeLinksProperties([link]))
            if p_link_properties.get('is_stub', False):
                self.stub_links.append(link)
            if p_link_properties.get('is_private', False):
                self.private_links.append(link)
        for (link_properties,
             p_link_properties) in zip(links_properties,
                                       p_links_properties):
            p_link_properties['iplhs'] = link_properties[0].iplhs
            p_link_properties['iprhs'] = link_properties[0].iprhs
            p_link_properties['net'] = link_properties[0].net
            p_link_properties['prefix'] = link_properties[0].prefix
        self.links_properties = p_links_properties
        # Create the management network
        if self.outband_emulation:
            # Remove the links router-controller
            for (link, link_properties) in zip(self._links, self.links_properties):
                if link[0] == self.controller or link[1] == self.controller or \
                        link[0] == self.wan_router or link[1] == self.wan_router:
                    self._links.remove(link)
                    self.links_properties.remove(link_properties)
            # Create the out of band management network
            for node in self._hosts + self.routers:
                link = (self.wan_router, node)
                link_properties = generator.getMgmtLinksProperties([link])
                self._links.append(link)
                self.links_properties.append({
                    'bw': 1000,
                    'delay': 0,
                    'iplhs': link_properties[0].iplhs,
                    'iprhs': link_properties[0].iprhs,
                    'net': link_properties[0].net,
                    'prefix': link_properties[0].prefix
                })
            link = (self.controller, self.wan_router)
            link_properties = generator.getMgmtLinksProperties([link])
            self._links.append(link)
            self.links_properties.append({
                'bw': 1000,
                'delay': 0,
                'iplhs': link_properties[0].iplhs,
                'iprhs': link_properties[0].iprhs,
                'net': link_properties[0].net,
                'prefix': link_properties[0].prefix
            })
        else:
            # In-Band emulation
            # Remove the links router-controller
            for (link, link_properties) in zip(self._links, self.links_properties):
                if link[0] == self.controller and link[1] in self.routers:
                    self._links.remove(link)
                    self.links_properties.remove(link_properties)
                    link = (self.wan_router, link[1])
                    self._links.append(link)
                elif link[0] in self.routers and link[1] == self.controller:
                    self._links.remove(link)
                    self.links_properties.remove(link_properties)
                    link = (self.wan_router, link[0])
                    self._links.append(link)
                if link in [(self.controller, self.wan_router), (self.wan_router, self.controller)]:
                    self._links.remove(link)
                    self.links_properties.remove(link_properties)
            link = (self.controller, self.wan_router)
            link_properties = generator.getCoreLinksProperties([link])
            self._links.append(link)
            self.links_properties.append({
                'bw': 1000,
                'delay': 0,
                'iplhs': link_properties[0].iplhs,
                'iprhs': link_properties[0].iprhs,
                'net': link_properties[0].net,
                'prefix': link_properties[0].prefix
            })
        # Add the management station
        self.mgmt = None
        if self.controller is not None:
            # Mgmt name
            self.mgmt = 'mgmt'
            generator.getHostsProperties([self.mgmt])
            # Create a link between mgmt station and controller
            self.mgmtIP = generator.getMgmtLinksProperties(
                [(self.mgmt, self.controller)])[0]
        # Init steps
        Topo.__init__(self, **opts)

    # Build the topology using parser information

    def build(self, *args, **params):
        # Init steps
        Topo.build(self, *args, **params)
        # Add controllers
        controller_loopbackip = None
        if self.controller is not None:
            # Assign mgmtip, loobackip, routerid
            scripts = self.controller_properties.get('scripts', [])
            loopbackIP = self.controller_properties.get('loopback')
            if loopbackIP is None:
                loopbackip = None
            else:
                loopbackip = "%s/%s" % (loopbackIP, LoopbackAllocator.prefix)
            # Add the controller to the topology
            self.addHost(name=self.controller, cls=SRv6Controller,
                         sshd=True, in_band=True,
                         scripts=scripts, loopbackip=loopbackip,
                         nodes=dict(),
                         inNamespace=True,
                         nets=[], routes=[], neighs=[],
                         interfaces=[], debug=self.debug)
            # Add node to the topology graph
            topology.add_node(self.controller,
                              loopbackip=loopbackip, type="controller")
            # Save controller loopback IP
            controller_loopbackip = loopbackip
            nodes_to_ips[self.controller] = list()
        # Add WAN router
        if self.wan_router is not None:
            # Assign mgmtip, loobackip, routerid
            scripts = self.wanrouter_properties.get('scripts', [])
            loopbackIP = self.wanrouter_properties['loopback']
            if loopbackIP is None:
                loopbackip = None
            else:
                loopbackip = "%s/%s" % (loopbackIP, LoopbackAllocator.prefix)
            # Add the WAN router to the topology
            self.addHost(name=self.wan_router,
                         cls=WANRouter, sshd=True,
                         scripts=scripts, neighs=[],
                         interfaces=[], nodes=dict(),
                         loopbackip=loopbackip, nets=[],
                         routes=[], debug=self.debug)
            # Add node to the topology graph
            topology.add_node(
                self.wan_router, loopbackip=loopbackip, type="wanrouter")
            nodes_to_ips[self.wan_router] = list()
        # Add routers
        for router, router_properties in zip(self.routers,
                                             self.routers_properties):
            # Assign mgmtip, loobackip, routerid
            scripts = router_properties.get('scripts', [])
            routerid = router_properties['routerid']
            routernet = router_properties['routernet']
            loopbackIP = router_properties['loopback']
            if loopbackIP is None:
                loopbackip = None
            else:
                loopbackip = "%s/%s" % (loopbackIP, LoopbackAllocator.prefix)
            # Enable ospfd?
            enable_ospf = router in self.ospf_routers
            # Add the router to the topology
            self.addHost(name=router,
                         cls=SRv6Router, sshd=True,
                         nodes=dict(), loopbackip=loopbackip,
                         routerid=routerid, scripts=scripts,
                         routernet=routernet,
                         use_ipv4_addressing=self.use_ipv4_addressing,
                         nets=[], routes=[], neighs=[], interfaces=[],
                         enable_ospf=enable_ospf, debug=self.debug)
            # Save mapping node to loopbackip
            if loopbackIP is not None:
                nodes_to_loopbackip[router] = str(loopbackIP)
            # Add node to the topology graph
            topology.add_node(router, loopbackip=loopbackip,
                              routerid=routerid, type="router")
            nodes_to_ips[router] = list()
        # Add hosts
        for host, host_properties in zip(self._hosts, self.hosts_properties):
            # Assign mgmtip, loobackip, routerid
            scripts = host_properties.get('scripts', [])
            loopbackIP = host_properties['loopback']
            if loopbackIP is None:
                loopbackip = None
            else:
                loopbackip = "%s/%s" % (loopbackIP, LoopbackAllocator.prefix)
            # Add the host to the topology
            self.addHost(name=host, cls=MHost,
                         sshd=True, nodes=dict(),
                         loopbackip=loopbackip, nets=[], neighs=[],
                         interfaces=[], routes=[],
                         scripts=scripts, debug=self.debug)
            # Add node to the topology graph
            topology.add_node(host, loopbackip=loopbackip, type="host")
            nodes_to_ips[host] = list()
        controller_wan_router_net = None
        # Iterate over the links and generate them
        for link, link_properties in zip(self._links,
                                         self.links_properties):
            # Get the left hand side of the pair
            lhs = link[0]
            # Get the right hand side of the pair
            rhs = link[1]
            # Create the core link
            self.addLink(lhs, rhs, bw=link_properties['bw'],
                         delay=link_properties['delay'])
            # Get Port number
            portNumber = self.port(lhs, rhs)
            # Create lhs_intf
            lhsintf = "%s-eth%d" % (lhs, portNumber[0])
            # Create rhs_intf
            rhsintf = "%s-eth%d" % (rhs, portNumber[1])
            # Assign a data-plane net to this link
            net = link_properties['net']
            # Prefix
            prefix = link_properties['prefix']
            # Get lhs ip
            lhsip = "%s/%d" % (link_properties['iplhs'],
                               prefix)
            # Get rhs ip
            rhsip = "%s/%d" % (link_properties['iprhs'],
                               prefix)
            # Add edge to the topology
            topology.add_edge(lhs, rhs, lhs_intf=lhsintf,
                              rhs_intf=rhsintf, lhs_ip=lhsip, rhs_ip=rhsip)
            # Add the reverse edge to the topology
            topology.add_edge(rhs, lhs, lhs_intf=rhsintf,
                              rhs_intf=lhsintf, lhs_ip=rhsip, rhs_ip=lhsip)
            # Configure the cost of the nets
            cost = link_properties.get('cost')
            is_stub = (lhs, rhs) in self.stub_links
            is_private = (lhs, rhs) in self.private_links
            # Save net
            lhsnet = {'intf': lhsintf, 'ip': lhsip, 'net': net, 'cost': cost,
                      'bw': link_properties['bw'], 'stub': is_stub, 'is_private': is_private}
            rhsnet = {'intf': rhsintf, 'ip': rhsip, 'net': net, 'cost': cost,
                      'bw': link_properties['bw'], 'stub': is_stub, 'is_private': is_private}
            self.nodeInfo(lhs)['nets'].append(lhsnet)
            self.nodeInfo(rhs)['nets'].append(rhsnet)
            # Save neighs
            self.nodeInfo(lhs)['neighs'].append(link_properties['iplhs'])
            self.nodeInfo(rhs)['neighs'].append(link_properties['iprhs'])
            # Save interfaces
            self.nodeInfo(lhs)['interfaces'].append((rhs, lhsintf))
            self.nodeInfo(rhs)['interfaces'].append((lhs, rhsintf))
            nodes_to_ips[lhs].append(link_properties['iplhs'])
            nodes_to_ips[rhs].append(link_properties['iprhs'])
            # Default via
            default_via = self.default_vias.get(lhs, None)
            if default_via is not None and default_via == rhs:
                self.nodeInfo(lhs)['default_via'] = link_properties['iprhs']
            default_via = self.default_vias.get(rhs, None)
            if default_via is not None and default_via == lhs:
                self.nodeInfo(rhs)['default_via'] = link_properties['iplhs']
            # Get the controller - WANRouter net
            if lhs == self.controller and rhs == self.wan_router:
                controller_wan_router_net = net
            elif lhs == self.wan_router and rhs == self.controller:
                controller_wan_router_net = net
        # Iterate over the mgmt links and generate them
        for link, link_properties in zip(self._links,
                                         self.links_properties):
            # Get the left hand side of the pair
            lhs = link[0]
            # Get the right hand side of the pair
            rhs = link[1]
            # Get Port number
            portNumber = self.port(lhs, rhs)
            # Create lhs_intf
            lhsintf = "%s-eth%d" % (lhs, portNumber[0])
            # Create rhs_intf
            rhsintf = "%s-eth%d" % (rhs, portNumber[1])
            # Assign a data-plane net to this link
            net = link_properties['net']
            # Prefix
            prefix = link_properties['prefix']
            # Get lhs ip
            lhsip = "%s/%d" % (link_properties['iplhs'],
                               prefix)
            # Get rhs ip
            rhsip = "%s/%d" % (link_properties['iprhs'],
                               prefix)
            # Set the routes and the default vias
            if (lhs == self.controller and rhs == self.wan_router) or \
                    (lhs == self.wan_router and rhs == self.controller):
                # Link between controller and WAN router
                controller = self.controller
                wanrouter = self.wan_router
                controller_ip = link_properties['iplhs'] if lhs == controller else link_properties['iprhs']
                wanrouter_ip = link_properties['iprhs'] if rhs == wanrouter else link_properties['iplhs']
                self.nodeInfo(controller)['default_via'] = wanrouter_ip
                if not self.outband_emulation and controller_loopbackip is not None:
                    self.nodeInfo(wanrouter)['routes'].append(
                        {'dest': controller_loopbackip, 'via': controller_ip})
            elif (lhs == self.wan_router and rhs in self.routers) or \
                    (lhs in self.routers and rhs == self.wan_router):
                # Link between the WAN router and a router
                router = lhs if rhs == self.wan_router else rhs
                wanrouter = self.wan_router
                router_ip = link_properties['iplhs'] if lhs == router else link_properties['iprhs']
                wanrouter_ip = link_properties['iprhs'] if rhs == wanrouter else link_properties['iplhs']
                if not self.outband_emulation:
                    self.nodeInfo(wanrouter)['default_via'] = router_ip
                    if controller_loopbackip is not None:
                        self.nodeInfo(router)['routes'].append(
                            {'dest': controller_loopbackip, 'via': wanrouter_ip})
                if self.controller is not None:
                    self.nodeInfo(self.controller)['nodes'][router] = router_ip
                self.nodeInfo(router)['routes'].append(
                    {'dest': controller_wan_router_net, 'via': wanrouter_ip})
            elif (lhs == self.wan_router and rhs in self._hosts) or \
                    (lhs in self._hosts and rhs == self.wan_router):
                # Link between the WAN router and a host
                host = lhs if rhs == self.wan_router else rhs
                wanrouter = self.wan_router
                host_ip = link_properties['iplhs'] if lhs == host else link_properties['iprhs']
                wanrouter_ip = link_properties['iprhs'] if rhs == wanrouter else link_properties['iplhs']
                if not self.outband_emulation:
                    if controller_loopbackip is not None:
                        self.nodeInfo(host)['routes'].append(
                            {'dest': controller_loopbackip, 'via': wanrouter_ip})
                if self.controller is not None:
                    self.nodeInfo(self.controller)['nodes'][host] = host_ip
                self.nodeInfo(host)['routes'].append(
                    {'dest': controller_wan_router_net, 'via': wanrouter_ip})
        # Store the IP addresses of the nodes
        nodes = self.routers + self._hosts
        if self.controller is not None:
            nodes += [self.controller]
        for node in nodes:
            if node in nodes_to_loopbackip:
                if self.controller is not None and node not in self.nodeInfo(self.controller)['nodes']:
                    self.nodeInfo(self.controller)[
                        'nodes'][node] = nodes_to_loopbackip[node]
                for node2 in nodes:
                    self.nodeInfo(node2)[
                        'nodes'][node] = nodes_to_loopbackip[node]
            else:
                if self.controller is not None and node not in self.nodeInfo(self.controller)['nodes'] and \
                        len(nodes_to_ips[node]) > 0:
                    self.nodeInfo(self.controller)[
                        'nodes'][node] = nodes_to_ips[node][0]
                for node2 in nodes:
                    self.nodeInfo(node2)['nodes'][node] = nodes_to_ips[node][0]
        # Configure the management station
        if self.controller is not None:
            # Create the mgmt node in the root namespace
            self.addHost(name=self.mgmt, cls=MHost, sshd=False,
                         use_ipv4_addressing=self.use_ipv4_addressing,
                         inNamespace=False, nets=[], routes=[])
            # Create a link between mgmt switch and mgmt station
            self.addLink(self.mgmt, self.controller, bw=1000, delay=0)
            # Get Port number
            portNumber = self.port(self.mgmt, self.controller)
            # Create lhs_intf
            lhsintf = "%s-eth%d" % (self.mgmt, portNumber[0])
            # Create rhs_intf
            rhsintf = "%s-eth%d" % (self.controller, portNumber[1])
            net = {
                'intf': lhsintf,
                'ip': '%s/%s' % (self.mgmtIP.iplhs, self.mgmtIP.prefix),
                'bw': 1000,
                'delay': 0,
                'net': self.mgmtIP.net,
            }
            self.nodeInfo(self.mgmt)['nets'].append(net)
            net = {
                'intf': rhsintf,
                'ip': '%s/%s' % (self.mgmtIP.iprhs, self.mgmtIP.prefix),
                'bw': 1000,
                'delay': 0,
                'net': self.mgmtIP.net,
            }
            self.nodeInfo(self.controller)['nets'].append(net)
            self.nodeInfo(self.mgmt)['routes'].append(
                {'dest': self.mgmtIP.net, 'via': self.mgmtIP.iprhs})
            self.nodeInfo(self.mgmt)['routes'].append(
                {'dest': self._net, 'via': self.mgmtIP.iprhs})
            #self.nodeInfo(self.mgmt)['routes'].append({'dest': self.customer_facing_net, 'via': self.mgmtIP.iplhs})
            #self.nodeInfo(self.mgmt)['routes'].append({'dest': self.access_net, 'via': self.mgmtIP.iplhs})
            self.nodeInfo(self.mgmt)['routes'].append(
                {'dest': controller_loopbackip, 'via': self.mgmtIP.iprhs})
            #self.nodeInfo(self.mgmt)['routes'].append({'dest': controller_wan_router_net, 'via': self.mgmtIP.iplhs})
            net = {
                'intf': lhsintf,
                'ip': '10.255.255.254/31',
                'bw': 1000,
                'delay': 0,
                'net': '10.255.255.254/31',
            }
            self.nodeInfo(self.mgmt)['nets'].append(net)
            net = {
                'intf': rhsintf,
                'ip': '10.255.255.255/31',
                'bw': 1000,
                'delay': 0,
                'net': '10.255.255.254/31',
            }
            self.nodeInfo(self.controller)['nets'].append(net)


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
    os.system('sudo killall sshd zebra ospf6d ospfd staticd')
    # Kill all the started daemons
    os.system('bash scripts/clean.sh')
    # Restart root ssh daemon
    os.system('service sshd restart')


# Utility function to deploy Mininet topology
def deploy(options):
    # Retrieves options
    debug = options.debug
    topologyFile = options.topology
    clean_all = options.clean_all
    no_cli = options.no_cli
    ipv4_addressing = options.ipv4_addressing
    #firewall_type = options.firewall
    # Clean all - clean and exit
    if clean_all:
        stopAll()
        return
    # Set Mininet log level to info
    setLogLevel('info')
    # Create Mininet topology
    topo = SRv6Topo(topo=topologyFile,
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
    # Parse input parameters
    (options, args) = parser.parse_args()
    # Done, return
    return options


if __name__ == '__main__':
    # Let's parse input parameters
    opts = parseOptions()
    # Deploy topology
    deploy(opts)
