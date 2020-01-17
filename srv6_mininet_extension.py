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
        # Stub links
        self.stub_links = list()
        # Private links
        self.private_links = list()
        # Save parsed data
        self.routers = parser.getRouters()
        p_routers_properties = parser.getRoutersProperties()
        self._hosts = parser.getHosts()
        p_hosts_properties = parser.getHostsProperties()
        self.controllers = parser.getControllers()
        p_controllers_properties = parser.getControllersProperties()
        # Identify ospf routers, wan router and default routes
        self.ospf_routers = list()
        self.default_vias = dict()
        self.wan_router = None
        for router, p_router_properties in zip(self.routers, p_routers_properties):
            if p_router_properties.get('enable_ospf', False):
                self.ospf_routers.append(router)
            self.default_vias[router] = p_router_properties.get('default_via', None)
            if p_router_properties.get('type') == 'WANRouter':
                if self.wan_router is not None:
                    error('Error: Multi-controller topologies are not supported')
                    exit(-1)
                self.wan_router = router
        # Identify default via for the hosts
        for host, p_host_properties in zip(self._hosts, p_hosts_properties):
            self.default_vias[host] = p_host_properties.get('default_via', None)
        # Identify the controller
        if len(self.controllers) == 0:
            self.controller = None
            #self.p_controller_properties = None
            self.outband_emulation = False
        elif len(self.controllers) == 1:
            self.controller = self.controllers[0]
            self.outband_emulation = p_controllers_properties[0].get('outband', False)
        if len(self.controllers) > 1:
            error('Error: Multi-controller topologies are not supported')
            exit(-1)
        # Process links
        self.core_links = parser.getCoreLinks()
        p_core_links_properties = parser.getCoreLinksProperties()
        self.edge_links = parser.getEdgeLinks()
        p_edge_links_properties = parser.getEdgeLinksProperties()
        self.mgmt_links = parser.getMgmtLinks()
        p_mgmt_links_properties = parser.getMgmtLinksProperties()
        # Properties generator
        if self.use_ipv4_addressing:
            generator = IPv4PropertiesGenerator()
            self.netprefix = IPv4NetAllocator.prefix
            self._net = generator.netAllocator.net
            self.customer_facing_net = generator.customerFacingNetAllocator.net
            self.access_net = generator.accessNetAllocator.net
            self.mgmtNet = generator.mgmtNetAllocator.net
            self.mgmtNet = generator.mgmtNetAllocator.net
        else:
            generator = IPv6PropertiesGenerator()
            self.netprefix = IPv6NetAllocator.prefix
            self._net = generator.netAllocator.net
            self.customer_facing_net = generator.customerFacingNetAllocator.net
            self.access_net = generator.accessNetAllocator.net
            self.mgmtNet = generator.mgmtNetAllocator.net
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
        # Generation of the core links parameters
        core_links_properties = []
        for (core_link,
             p_core_link_properties) in zip(self.core_links,
                                            p_core_links_properties):
            core_link = (core_link[0], core_link[1])
            if core_link[0] == self.wan_router or core_link[1] == self.wan_router:
                self.core_links.remove(core_link)
                p_core_links_properties.remove(p_core_link_properties)
                if not self.outband_emulation:
                    self.mgmt_links.append(core_link)
                    p_mgmt_links_properties.append(p_core_link_properties)
                continue
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
            elif type == 'mgmt':
                if self.outband_emulation:
                    core_links_properties.append(generator
                                                 .getMgmtLinksProperties([core_link]))
                else:
                    core_links_properties.append(generator
                                                 .getCoreLinksProperties([core_link]))
            else:
                core_links_properties.append(generator
                                             .getCoreLinksProperties([core_link]))                                            
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
            if edge_link[0] == self.wan_router or edge_link[1] == self.wan_router:
                self.edge_links.remove(edge_link)
                p_edge_links_properties.remove(p_edge_link_properties)
                if not self.outband_emulation:
                    self.mgmt_links.append(edge_link)
                    p_mgmt_links_properties.append(p_edge_link_properties)
                continue
            # We treat controller-device links as core links
            #if edge_link[0] == self.controller or edge_link[1] == self.controller:
            #    edge_links_properties.append(generator
            #                                 .getCoreLinksProperties([edge_link]))
            #else:
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
            elif type == 'mgmt':
                if self.outband_emulation:
                    edge_links_properties.append(generator
                                                 .getMgmtLinksProperties([edge_link]))
                else:
                    edge_links_properties.append(generator
                                                 .getCoreLinksProperties([edge_link]))
            else:
                edge_links_properties.append(generator
                                                .getEdgeLinksProperties([edge_link]))
            # Stub links identification
            if p_edge_link_properties.get('is_stub', True):
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
        # Generation of the mgmt links parameters
        mgmt_links_properties = []
        for (mgmt_link,
             p_mgmt_link_properties) in zip(self.mgmt_links,
                                            p_mgmt_links_properties):
            mgmt_link = (mgmt_link[0], mgmt_link[1])
            if self.outband_emulation:
                if mgmt_link[0] == self.wan_router or mgmt_link[1] == self.wan_router:
                    self.mgmt_links.remove(mgmt_link)
                    p_mgmt_links_properties.remove(p_mgmt_link_properties)
                    continue
            type = p_mgmt_link_properties.get('type', 'mgmt')
            if type == 'core':
                mgmt_links_properties.append(generator
                                                .getCoreLinksProperties([mgmt_link]))
            elif type == 'edge':
                mgmt_links_properties.append(generator
                                                .getEdgeLinksProperties([mgmt_link]))
            elif type == 'access':
                mgmt_links_properties.append(generator
                                                .getAccessLinksProperties([mgmt_link]))
            elif type == 'mgmt':
                if self.outband_emulation:
                    mgmt_links_properties.append(generator
                                                 .getMgmtLinksProperties([mgmt_link]))
                else:
                    mgmt_links_properties.append(generator
                                                 .getCoreLinksProperties([mgmt_link]))
            else:
                mgmt_links_properties.append(generator
                                                .getMgmtLinksProperties([mgmt_link]))
            # Stub links identification
            if p_mgmt_link_properties.get('is_stub', False):
                self.stub_links.append(mgmt_link)
            # Private links identification
            if p_mgmt_link_properties.get('is_private', False):
                self.private_links.append(mgmt_link)
        for (mgmt_link_properties,
             p_mgmt_link_properties) in zip(mgmt_links_properties,
                                            p_mgmt_links_properties):
            p_mgmt_link_properties['iplhs'] = mgmt_link_properties[0].iplhs
            p_mgmt_link_properties['iprhs'] = mgmt_link_properties[0].iprhs
            p_mgmt_link_properties['net'] = mgmt_link_properties[0].net
            p_mgmt_link_properties['prefix'] = mgmt_link_properties[0].prefix
        self.mgmt_links_properties = p_mgmt_links_properties

        if self.outband_emulation:
            if self.controller is not None:
                mgmt_link = (self.controller, self.wan_router)
                self.mgmt_links.append(mgmt_link)
                mgmt_link_properties = (generator
                                        .getMgmtLinksProperties([mgmt_link]))
                self.mgmt_links_properties.append({
                    'bw': 1000,
                    'delay': 0,
                    'iplhs': mgmt_link_properties[0].iplhs,
                    'iprhs': mgmt_link_properties[0].iprhs,
                    'net': mgmt_link_properties[0].net,
                    'prefix': mgmt_link_properties[0].prefix
                })
            if self.wan_router is not None:
                wan_router = self.wan_router
            elif self.controller is not None:
                wan_router = self.controller
            else:
                wan_router = None
            if wan_router is not None:
                for router in self.routers:
                    mgmt_link = (router, wan_router)
                    if router != wan_router:
                        self.mgmt_links.append(mgmt_link)
                    mgmt_link_properties = (generator
                                            .getMgmtLinksProperties([mgmt_link]))
                    self.mgmt_links_properties.append({
                        'bw': 1000,
                        'delay': 0,
                        'iplhs': mgmt_link_properties[0].iplhs,
                        'iprhs': mgmt_link_properties[0].iprhs,
                        'net': mgmt_link_properties[0].net,
                        'prefix': mgmt_link_properties[0].prefix
                    })
                for host in self._hosts:
                    mgmt_link = (host, wan_router)
                    if host != wan_router:
                        self.mgmt_links.append(mgmt_link)
                    mgmt_link_properties = (generator
                                            .getMgmtLinksProperties([mgmt_link]))
                    self.mgmt_links_properties.append({
                        'bw': 1000,
                        'delay': 0,
                        'iplhs': mgmt_link_properties[0].iplhs,
                        'iprhs': mgmt_link_properties[0].iprhs,
                        'net': mgmt_link_properties[0].net,
                        'prefix': mgmt_link_properties[0].prefix
                    })
        self.mgmt = None
        if self.controller is not None:
            # Mgmt name
            self.mgmt = 'mgmt'
            generator.getHostsProperties([self.mgmt])
            # Create a link between mgmt station and controller
            self.mgmtIP = generator.getMgmtLinksProperties([(self.mgmt, self.controller)])[0]
        # Init steps
        Topo.__init__(self, **opts)


    # Build the topology using parser information
    def build(self, *args, **params):
        #self.vias = dict()
        # Init steps
        Topo.build(self, *args, **params)
        # Add routers
        id = 1
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
            if router_properties.get('type') == 'WANRouter':
                # Add the WAN router to the topology
                self.addHost(name=router, cls=WANRouter, sshd=True,
                             scripts=scripts, neighs=[], interfaces=[], nodes=dict(),
                             loopbackip=loopbackip, nets=[], routes=[], debug=self.debug)
                # Add node to the topology graph
                topology.add_node(router, loopbackip=loopbackip, type="wanrouter")
            else:
                # Enable ospfd?
                enable_ospf = router in self.ospf_routers
                # Add the router to the topology
                self.addHost(name=router, cls=SRv6Router, sshd=True, id=id, nodes=dict(),
                            loopbackip=loopbackip, routerid=routerid, scripts=scripts,
                            routernet=routernet, use_ipv4_addressing=self.use_ipv4_addressing,
                            nets=[], routes=[], neighs=[], interfaces=[], enable_ospf=enable_ospf, debug=self.debug)
                # Save mapping node to loopbackip
                if loopbackIP is not None:
                    nodes_to_loopbackip[router] = str(loopbackIP)
                # Add node to the topology graph
                topology.add_node(router, loopbackip=loopbackip,
                                routerid=routerid, type="router")
                id += 1
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
            self.addHost(name=host, cls=MHost, sshd=True, nodes=dict(),
                            loopbackip=loopbackip, nets=[], neighs=[], interfaces=[], routes=[],
                            scripts=scripts, debug=self.debug)
            # Add node to the topology graph
            topology.add_node(host, loopbackip=loopbackip, type="host")
            nodes_to_ips[host] = list()
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
            self.addHost(name=self.controller, cls=SRv6Controller, sshd=True, in_band=True,
                            scripts=scripts, loopbackip=loopbackip, nodes=dict(),
                            inNamespace=not self.outband_emulation,
                            nets=[], routes=[], neighs=[], interfaces=[], debug=self.debug)
            # Add node to the topology graph
            topology.add_node(self.controller, loopbackip=loopbackip, type="controller")
            # Save controller loopback IP
            controller_loopbackip = loopbackip
            nodes_to_ips[self.controller] = list()
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
            # Save neighs
            self.nodeInfo(lhs)['neighs'].append(core_link_properties['iplhs'])
            self.nodeInfo(rhs)['neighs'].append(core_link_properties['iprhs'])
            # Save interfaces
            self.nodeInfo(lhs)['interfaces'].append((rhs, lhsintf))
            self.nodeInfo(rhs)['interfaces'].append((lhs, rhsintf))
            nodes_to_ips[lhs].append(core_link_properties['iplhs'])
            nodes_to_ips[rhs].append(core_link_properties['iprhs'])
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
            lhsip = edge_link_properties['iplhs']
            # Get rhs ip
            rhsip = edge_link_properties['iprhs']
            # Prefix
            prefix = edge_link_properties['prefix']
            net = net.__str__()
            # Save neighs
            self.nodeInfo(lhs)['neighs'].append(rhsip)
            self.nodeInfo(rhs)['neighs'].append(lhsip)
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
            lhsnet = {
                'intf': lhsintf, 'ip': lhsip, 'net': net,
                'cost': cost, 'bw': edge_link_properties['bw'],
                'stub': is_stub, 'is_private': is_private
            }
            rhsnet = {
                'intf': rhsintf, 'ip': rhsip, 'net': net,
                'cost': cost, 'bw': edge_link_properties['bw'],
                'stub': is_stub, 'is_private': is_private
            }
            self.nodeInfo(lhs)['nets'].append(lhsnet)
            self.nodeInfo(rhs)['nets'].append(rhsnet)
            # Save interfaces
            self.nodeInfo(lhs)['interfaces'].append((rhs, lhsintf))
            self.nodeInfo(rhs)['interfaces'].append((lhs, rhsintf))
            nodes_to_ips[lhs].append(edge_link_properties['iplhs'])
            nodes_to_ips[rhs].append(edge_link_properties['iprhs'])
            # Default via
            default_via = self.default_vias.get(lhs, None)
            if default_via is not None and default_via == rhs:
                self.nodeInfo(lhs)['default_via'] = edge_link_properties['iprhs']
            default_via = self.default_vias.get(rhs, None)
            if default_via is not None and default_via == lhs:
                self.nodeInfo(rhs)['default_via'] = edge_link_properties['iplhs']
        # Iterate over the mgmt links and generate them
        controller_wan_router_net = None
        for mgmt_link, mgmt_link_properties in zip(self.mgmt_links,
                                                   self.mgmt_links_properties):
            # Get the left hand side of the pair
            lhs = mgmt_link[0]
            # Get the right hand side of the pair
            rhs = mgmt_link[1]
            # Create the core link
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
            # Prefix
            prefix = mgmt_link_properties['prefix']
            # Get lhs ip
            lhsip = "%s/%d" % (mgmt_link_properties['iplhs'],
                               prefix)
            # Get rhs ip
            rhsip = "%s/%d" % (mgmt_link_properties['iprhs'],
                               prefix)
            # Add edge to the topology
            topology.add_edge(
                lhs, rhs, lhs_intf=lhsintf,
                rhs_intf=rhsintf, lhs_ip=lhsip, rhs_ip=rhsip
            )
            # Add the reverse edge to the topology
            topology.add_edge(
                rhs, lhs, lhs_intf=rhsintf,
                rhs_intf=lhsintf, lhs_ip=rhsip, rhs_ip=lhsip
            )
            # Configure the cost of the nets
            cost = mgmt_link_properties.get('cost')
            is_stub = (lhs, rhs) in self.stub_links
            is_private = (lhs, rhs) in self.private_links
            # Save net
            lhsnet = {
                'intf': lhsintf, 'ip': lhsip, 'net': net,
                'cost': cost, 'bw': mgmt_link_properties['bw'],
                'stub': is_stub, 'is_private': is_private
            }
            rhsnet = {
                'intf': rhsintf, 'ip': rhsip, 'net': net,
                'cost': cost, 'bw': mgmt_link_properties['bw'],
                'stub': is_stub, 'is_private': is_private
            }
            self.nodeInfo(lhs)['nets'].append(lhsnet)
            self.nodeInfo(rhs)['nets'].append(rhsnet)
            # Save neighs
            self.nodeInfo(lhs)['neighs'].append(mgmt_link_properties['iplhs'])
            self.nodeInfo(rhs)['neighs'].append(mgmt_link_properties['iprhs'])
            # Save interfaces
            self.nodeInfo(lhs)['interfaces'].append((rhs, lhsintf))
            self.nodeInfo(rhs)['interfaces'].append((lhs, rhsintf))
            if lhs == self.controller and rhs == self.wan_router or \
                    rhs == self.controller and lhs == self.wan_router:
                controller_wan_router_net = net
            nodes_to_ips[lhs].append(mgmt_link_properties['iplhs'])
            nodes_to_ips[rhs].append(mgmt_link_properties['iprhs'])
            # Default via
            default_via = self.default_vias.get(lhs, None)
            if default_via is not None and default_via == rhs:
                self.nodeInfo(lhs)['default_via'] = mgmt_link_properties['iprhs']
            default_via = self.default_vias.get(rhs, None)
            if default_via is not None and default_via == lhs:
                self.nodeInfo(rhs)['default_via'] = mgmt_link_properties['iplhs']
        # Iterate over the mgmt links and generate them
        for mgmt_link, mgmt_link_properties in zip(self.mgmt_links,
                                                    self.mgmt_links_properties):
            # Get the left hand side of the pair
            lhs = mgmt_link[0]
            # Get the right hand side of the pair
            rhs = mgmt_link[1]
            if lhs == self.controller and rhs == self.wan_router:
                #controller_wan_router_net = net
                # Configure the default via of the controller and the WAN router
                if self.outband_emulation:
                    self.nodeInfo(self.controller)['routes'].append({'dest': self.mgmtNet, 'via': mgmt_link_properties['iprhs']})
                else:
                    self.nodeInfo(self.controller)['routes'].append({'dest': self._net, 'via': mgmt_link_properties['iprhs']})
                    self.nodeInfo(self.controller)['routes'].append({'dest': self.customer_facing_net, 'via': mgmt_link_properties['iprhs']})
                    self.nodeInfo(self.controller)['routes'].append({'dest': self.access_net, 'via': mgmt_link_properties['iprhs']})
                self.nodeInfo(self.controller)['default_via'] = mgmt_link_properties['iprhs']
                if controller_loopbackip is not None:
                    self.nodeInfo(self.wan_router)['routes'].append({'dest': controller_loopbackip, 'via': mgmt_link_properties['iplhs']})
            elif rhs == self.controller and lhs == self.wan_router:
                # Configure the default via of the controller and the WAN router
                if self.outband_emulation:
                    self.nodeInfo(self.controller)['routes'].append({'dest': self.mgmtNet, 'via': mgmt_link_properties['iplhs']})
                else:
                    self.nodeInfo(self.controller)['routes'].append({'dest': self._net, 'via': mgmt_link_properties['iplhs']})
                    self.nodeInfo(self.controller)['routes'].append({'dest': self.customer_facing_net, 'via': mgmt_link_properties['iplhs']})
                    self.nodeInfo(self.controller)['routes'].append({'dest': self.access_net, 'via': mgmt_link_properties['iplhs']})
                self.nodeInfo(self.controller)['default_via'] = mgmt_link_properties['iplhs']
                if controller_loopbackip is not None:
                    self.nodeInfo(self.wan_router)['routes'].append({'dest': controller_loopbackip, 'via': mgmt_link_properties['iprhs']})
            elif lhs == self.controller and rhs in self.routers:
                #controller_wan_router_net = net
                # Configure the default via of the controller and the WAN router
                if self.outband_emulation:
                    self.nodeInfo(self.controller)['routes'].append({'dest': self.mgmtNet, 'via': mgmt_link_properties['iprhs']})
                else:
                    self.nodeInfo(self.controller)['routes'].append({'dest': self._net, 'via': mgmt_link_properties['iprhs']})
                    self.nodeInfo(self.controller)['routes'].append({'dest': self.customer_facing_net, 'via': mgmt_link_properties['iprhs']})
                    self.nodeInfo(self.controller)['routes'].append({'dest': self.access_net, 'via': mgmt_link_properties['iprhs']})
                self.nodeInfo(self.controller)['default_via'] = mgmt_link_properties['iprhs']
                if controller_loopbackip is not None:
                    self.nodeInfo(self.wan_router)['routes'].append({'dest': controller_loopbackip, 'via': mgmt_link_properties['iplhs']})
            elif rhs in self.routers and lhs == self.wan_router:
                # Configure the default via of the controller and the WAN router
                if self.outband_emulation:
                    self.nodeInfo(self.controller)['routes'].append({'dest': self.mgmtNet, 'via': mgmt_link_properties['iplhs']})
                else:
                    self.nodeInfo(self.controller)['routes'].append({'dest': self._net, 'via': mgmt_link_properties['iplhs']})
                    self.nodeInfo(self.controller)['routes'].append({'dest': self.customer_facing_net, 'via': mgmt_link_properties['iplhs']})
                    self.nodeInfo(self.controller)['routes'].append({'dest': self.access_net, 'via': mgmt_link_properties['iplhs']})
                self.nodeInfo(self.controller)['default_via'] = mgmt_link_properties['iplhs']
                if controller_loopbackip is not None:
                    self.nodeInfo(self.wan_router)['routes'].append({'dest': controller_loopbackip, 'via': mgmt_link_properties['iprhs']})
            elif rhs == self.wan_router and lhs in self.routers:
                # Add the route to the router
                if controller_loopbackip is not None:
                    self.nodeInfo(lhs)['routes'].append({'dest': controller_loopbackip, 'via': mgmt_link_properties['iprhs']})
                self.nodeInfo(lhs)['routes'].append({'dest': controller_wan_router_net, 'via': mgmt_link_properties['iprhs']})
                if not self.outband_emulation:
                    self.nodeInfo(rhs)['default_via'] = mgmt_link_properties['iplhs']
                if self.controller is not None:
                    self.nodeInfo(self.controller)['nodes'][lhs] = mgmt_link_properties['iplhs']
            elif lhs == self.wan_router and rhs in self.routers:
                # Add the route to the router
                if controller_loopbackip is not None:
                    self.nodeInfo(rhs)['routes'].append({'dest': controller_loopbackip, 'via': mgmt_link_properties['iplhs']})
                self.nodeInfo(rhs)['routes'].append({'dest': controller_wan_router_net, 'via': mgmt_link_properties['iplhs']})
                if not self.outband_emulation:
                    self.nodeInfo(lhs)['default_via'] = mgmt_link_properties['iprhs']
                if self.controller is not None:
                    self.nodeInfo(self.controller)['nodes'][rhs] = mgmt_link_properties['iprhs']
            elif rhs == self.wan_router and lhs in self._hosts:
                # Add the route to the router
                if controller_loopbackip is not None:
                    self.nodeInfo(lhs)['routes'].append({'dest': controller_loopbackip, 'via': mgmt_link_properties['iprhs']})
                self.nodeInfo(lhs)['routes'].append({'dest': controller_wan_router_net, 'via': mgmt_link_properties['iprhs']})
                if not self.outband_emulation:
                    self.nodeInfo(rhs)['default_via'] = mgmt_link_properties['iplhs']
                if self.controller is not None:
                    self.nodeInfo(self.controller)['nodes'][lhs] = mgmt_link_properties['iplhs']
            elif lhs == self.wan_router and rhs in self._hosts:
                # Add the route to the router
                if controller_loopbackip is not None:
                    self.nodeInfo(rhs)['routes'].append({'dest': controller_loopbackip, 'via': mgmt_link_properties['iplhs']})
                self.nodeInfo(rhs)['routes'].append({'dest': controller_wan_router_net, 'via': mgmt_link_properties['iplhs']})
                if not self.outband_emulation:
                    self.nodeInfo(lhs)['default_via'] = mgmt_link_properties['iprhs']
                if self.controller is not None:
                    self.nodeInfo(self.controller)['nodes'][rhs] = mgmt_link_properties['iprhs']
        nodes = self.routers + self._hosts
        if self.controller is not None:
            nodes += [self.controller]
        for node in nodes:
            if node in nodes_to_loopbackip:
                if self.controller is not None and node not in self.nodeInfo(self.controller)['nodes']:
                    self.nodeInfo(self.controller)['nodes'][node] = nodes_to_loopbackip[node]
                for node2 in nodes:
                    self.nodeInfo(node2)['nodes'][node] = nodes_to_loopbackip[node]
            else:
                if self.controller is not None and node not in self.nodeInfo(self.controller)['nodes'] and \
                        len(nodes_to_ips[node]) > 0:
                    self.nodeInfo(self.controller)['nodes'][node] = nodes_to_ips[node][0]
                for node2 in nodes:
                    self.nodeInfo(node2)['nodes'][node] = nodes_to_ips[node][0]
        if not self.outband_emulation and self.mgmt is not None:
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
            print('%s/%s' % (self.mgmtIP.iplhs, self.mgmtIP.prefix))
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
            self.nodeInfo(self.mgmt)['routes'].append({'dest': self.mgmtIP.net, 'via': self.mgmtIP.iplhs})
            self.nodeInfo(self.mgmt)['routes'].append({'dest': self._net, 'via': self.mgmtIP.iplhs})
            #self.nodeInfo(self.mgmt)['routes'].append({'dest': self.customer_facing_net, 'via': self.mgmtIP.iplhs})
            #self.nodeInfo(self.mgmt)['routes'].append({'dest': self.access_net, 'via': self.mgmtIP.iplhs})
            self.nodeInfo(self.mgmt)['routes'].append({'dest': controller_loopbackip, 'via': self.mgmtIP.iplhs})
            self.nodeInfo(self.mgmt)['routes'].append({'dest': controller_wan_router_net, 'via': self.mgmtIP.iplhs})


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
