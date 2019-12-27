#!/usr/bin/python

##############################################################################################
# Copyright (C) 2018 Pier Luigi Ventre - (CNIT and University of Rome "Tor Vergata")
# Copyright (C) 2018 Stefano Salsano - (CNIT and University of Rome "Tor Vergata")
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
# Utils for Segment Routing IPv6
#
# @author Pier Luigi Ventre <pierventre@hotmail.com>
# @author Stefano Salsano <stefano.salsano@uniroma2.it>

from __future__ import absolute_import, division, print_function

# General imports
import os
import shutil
import time
import sys
import re
from datetime import datetime
# Mininet dependencies
from mininet.node import Host
from mininet.log import error
# SRv6 dependencies
from srv6_generators import RANGE_FOR_AREA_0

################## Setup these variables ##################

# Interval between two hello packets (in seconds)
HELLO_INTERVAL = 1
# How long we should be wait for hello packets
# before we declare the neighbor dead (in seconds)
DEAD_INTERVAL = 3
# How long we should be wait before retransmitting
# Database Description and Link State Request packets (in seconds)
RETRANSMIT_INTERVAL = 3
# The maximum time allowed between sending unsolicited
# multicast router advertisement from the interface (in seconds)
RA_INTERVAL = 10

###########################################################

# This workaround solves the issue of python commands
# executed outside the virtual environment
PYTHON_PATH = sys.executable

# nodes.sh file containing the nodes
NODES_SH = 'nodes.sh'
# neighs.sh containing the neighbors
NEIGHS_SH = 'neighs.sh'
# devid.sh file containing the device ID
DEVICEID_SH = 'devid.sh'
# hostname.sh file containing the hostname
HOSTNAME_SH = 'hostname.sh'
# interfaces.sh file containing the interfaces
INTERFACES_SH = 'interfaces.sh'


# Abstraction to model a SRv6Router
class SRv6Router(Host):

    def __init__(self, name, *args, **kwargs):

        dirs = ['/var/mininet']
        Host.__init__(self, name, privateDirs=dirs, *args, **kwargs)
        self.dir = "/tmp/%s" % name
        self.nets = []
        if os.path.exists(self.dir):
            shutil.rmtree(self.dir)
        if not os.path.exists(self.dir):
            os.makedirs(self.dir)
        if kwargs.get('debug', False):
            self.exec_cmd = self.cmdPrint
        else:
            self.exec_cmd = self.cmd

    # Config hook
    def config(self, **kwargs):

        # Init steps
        Host.config(self, **kwargs)
        # Iterate over the interfaces
        for intf in self.intfs.values():
            # Remove any configured address
            self.exec_cmd('ifconfig %s 0' % intf.name)
            # For the first one, let's configure the mgmt address
            if intf.name == kwargs.get('mgmtintf'):
                self.exec_cmd('ip a a %s dev %s' % (kwargs['mgmtip'], intf.name))
        # Let's write the hostname in /var/mininet/hostname
        self.exec_cmd("echo '" + self.name + "' > /var/mininet/hostname")
        # Let's write the hostname
        self.exec_cmd("echo 'HOSTNAME=%s' > %s/%s" % (self.name, self.dir, HOSTNAME_SH))
        # Let's write the id
        self.exec_cmd("echo 'DEVICEID='$(cat /proc/sys/kernel/random/uuid)'' > %s/%s" % (self.dir, DEVICEID_SH))
        # Let's write the neighbors
        if 'neighs' in kwargs:
            neighs_sh = '%s/%s' % (self.dir, NEIGHS_SH)
            with open(neighs_sh, 'w') as outfile:
                # Create header
                nodes = "declare -a NEIGHS=("
                # Iterate over management ips
                for neigh in kwargs['neighs']:
                    # Add the nodes one by one
                    nodes = nodes + "%s " % neigh
                if kwargs['neighs'] != []:
                    # Eliminate last character
                    nodes = nodes[:-1] + ")\n"
                else:
                    nodes = nodes + ")\n"
                # Write on the file
                outfile.write(nodes)
        # Let's write the interfaces
        if 'interfaces' in kwargs:
            interfaces_sh = '%s/%s' % (self.dir, INTERFACES_SH)
            with open(interfaces_sh, 'w') as outfile:
                # Create header
                nodes = "declare -A INTERFACES=("
                # Iterate over management ips
                for (neigh, intf) in kwargs['interfaces']:
                    # Add the nodes one by one
                    nodes = nodes + '[%s]=%s ' % (neigh, intf)
                if kwargs['interfaces'] != []:
                    # Eliminate last character
                    nodes = nodes[:-1] + ")\n"
                else:
                    nodes = nodes + ")\n"
                # Write on the file
                outfile.write(nodes)
        # Retrieve nets
        if kwargs.get('nets', None):
            self.nets = kwargs['nets']
        # If requested
        if kwargs['sshd']:
            # Let's start sshd daemon in the hosts
            self.exec_cmd('/usr/sbin/sshd -D &')
        # Configure the loopback address
        if kwargs.get('loopbackip', None):
            self.exec_cmd('ip a a %s dev lo' % (kwargs['loopbackip']))
            self.nets.append({
              'intf': 'lo',
              'ip': kwargs['loopbackip'],
              'net': kwargs['loopbackip']})
        # Enable IPv6 forwarding
        self.exec_cmd("sysctl -w net.ipv6.conf.all.forwarding=1")
        # Enable IPv4 forwarding
        self.exec_cmd("sysctl -w net.ipv4.conf.all.forwarding=1")
        # Disable Reverse Path Forwarding filter
        self.exec_cmd("sysctl -w net.ipv4.conf.all.rp_filter=0")
        # Enable SRv6 on the interface
        self.exec_cmd("sysctl -w net.ipv6.conf.all.seg6_enabled=1")
        # Disable RA accept (stateless address autoconfiguration)
        self.exec_cmd("sysctl -w net.ipv6.conf.all.accept_ra=0")
        # Force Linux to keep all IPv6 addresses on an interface down event
        self.exec_cmd("sysctl -w net.ipv6.conf.all.keep_addr_on_down=1")
        # Iterate over the interfaces
        for intf in self.intfs.values():
            # Enable IPv6 forwarding
            self.exec_cmd("sysctl -w net.ipv6.conf.%s.forwarding=1" % intf.name)
            # Enable IPv4 forwarding
            self.exec_cmd("sysctl -w net.ipv4.conf.%s.forwarding=1" % intf.name)
            # Disable Reverse Path Forwarding filter
            self.exec_cmd("sysctl -w net.ipv4.conf.%s.rp_filter=0" % intf.name)
            # Enable SRv6 on the interface
            self.exec_cmd("sysctl -w net.ipv6.conf.%s.seg6_enabled=1" % intf.name)
            # Disable RA accept (stateless address autoconfiguration)
            self.exec_cmd("sysctl -w net.ipv6.conf.%s.accept_ra=0" % intf.name)
            # Force Linux to keep all IPv6 addresses on an interface down event
            self.exec_cmd("sysctl -w net.ipv6.conf.%s.keep_addr_on_down=1" % intf.name)
        # Zebra and Quagga config
        if len(self.nets) > 0:
            if kwargs.get('use_ipv4_addressing', False):
                self.start_zebra_ipv4(**kwargs)
                if kwargs.get('enable_ospf', False):
                    self.start_ospfd(**kwargs)
                self.start_staticd_ipv4(**kwargs)
            else:
                self.start_zebra_ipv6(**kwargs)
                if kwargs.get('enable_ospf', False):
                    self.start_ospf6d(**kwargs)
                self.start_staticd_ipv6(**kwargs)
        # Run scripts
        self.exec_cmd('export PATH=%s:$PATH' % os.path.dirname(PYTHON_PATH))
        self.exec_cmd('$PATH')
        if 'scripts' in kwargs:
            for script in kwargs['scripts']:
                script_path = os.path.abspath(os.path.join('scripts', script))
                self.exec_cmd('cd %s' % self.dir)
                self.exec_cmd('bash %s &' % script_path)
        # Let's write the interfaces
        if 'nodes' in kwargs:
            nodes_sh = '%s/%s' % (self.dir, NODES_SH)
            with open(nodes_sh, 'w') as outfile:
                # Create header
                nodes = "declare -A NODES=("
                # Iterate over management ips
                for node, ip in kwargs['nodes'].items():
                    # Add the nodes one by one
                    nodes = nodes + '[%s]=%s ' % (node, ip)
                if kwargs['nodes'] != []:
                    # Eliminate last character
                    nodes = nodes[:-1] + ")\n"
                else:
                    nodes = nodes + ")\n"
                # Write on the file
                outfile.write(nodes)

    # Configure and start zebra for IPv6 emulation
    def start_zebra_ipv6(self, **kwargs):
        # Zebra and Quagga config
        if len(self.nets) > 0:
            zebra = open("%s/zebra.conf" % self.dir, 'w')
            zebra.write("! -*- zebra -*-\n!\nhostname %s\n" %
                        self.name)
            zebra.write("password srv6\nenable password srv6\n"
                        "log file %s/zebra.log\n!\n" % self.dir)
            # Iterate over the nets and build interface part of the configs
            for net in self.nets:
                # Non-loopback interface
                if net['intf'] != 'lo':
                    # Set the IPv6 address and the network
                    # discovery prefix in the zebra configuration
                    zebra.write("interface %s\n"
                                " link-detect\n"
                                " bandwidth %s\n"
                                " no ipv6 nd suppress-ra\n"
                                " ipv6 nd ra-interval %s\n"
                                " ipv6 address %s\n"
                                " ipv6 nd prefix %s\n!\n"
                                % (net['intf'], min(net['bw']*1000, 100000), RA_INTERVAL,
                                   net['ip'], net['net']))
            zebra.close()
            # Right permission and owners
            self.exec_cmd("chown frr /var/run")
            self.exec_cmd("chown frr %s/*.conf" % self.dir)
            self.exec_cmd("chown frr %s/." % self.dir)
            self.exec_cmd("chmod 640 %s/*.conf" % self.dir)
            self.start_time_zebra = datetime.now().replace(microsecond=0)
            # Start daemons
            self.exec_cmd("zebra -f %s/zebra.conf -d -z %s/zebra.sock -i "
                     "%s/zebra.pid" % (self.dir, self.dir, self.dir))

    def start_staticd_ipv4(self, **kwargs):
        staticd = open("%s/staticd.conf" % self.dir, 'w')
        staticd.write("! -*- staticd -*-\n!\nhostname %s\n" % self.name)
        staticd.write("password srv6\nlog file %s/staticd.log\n!\n" %
                    self.dir)
        # Configure the default via
        default_via = kwargs.get('default_via', None)
        if default_via is not None:
            staticd.write("ip route %s %s\n"  % ('0.0.0.0/0', default_via))
        # Configure the routes
        if kwargs.get('routes', None):
            for route in kwargs['routes']:
                dest = route['dest']
                via = route['via']
                staticd.write("ip route %s %s\n"  % (dest, via))
        staticd.close()
        self.exec_cmd("chown frr /var/run")
        self.exec_cmd("chown frr %s/*.conf" % self.dir)
        self.exec_cmd("chown frr %s/." % self.dir)
        self.exec_cmd("chmod 640 %s/*.conf" % self.dir)
        # Start daemons
        self.exec_cmd("staticd -f %s/staticd.conf -d -z %s/zebra.sock -i "
                        "%s/staticd.pid" % (self.dir, self.dir, self.dir))

    def start_staticd_ipv6(self, **kwargs):
        staticd = open("%s/staticd.conf" % self.dir, 'w')
        staticd.write("! -*- staticd -*-\n!\nhostname %s\n" % self.name)
        staticd.write("password srv6\nlog file %s/staticd.log\n!\n" %
                    self.dir)
        # Configure the default via
        default_via = kwargs.get('default_via', None)
        if default_via is not None:
            staticd.write("ipv6 route %s %s\n"  % ('::/0', default_via))
        # Add static route for router network
        if kwargs.get('routernet', None):
            routernet = kwargs['routernet']
            staticd.write("ipv6 route %s lo\n!\n" % routernet)
        # Configure the routes
        if kwargs.get('routes', None):
            for route in kwargs['routes']:
                dest = route['dest']
                via = route['via']
                staticd.write("ipv6 route %s %s\n"  % (dest, via))
        staticd.close()
        self.exec_cmd("chown frr /var/run")
        self.exec_cmd("chown frr %s/*.conf" % self.dir)
        self.exec_cmd("chown frr %s/." % self.dir)
        self.exec_cmd("chmod 640 %s/*.conf" % self.dir)
        # Start daemons
        self.exec_cmd("staticd -f %s/staticd.conf -d -z %s/zebra.sock -i "
                        "%s/staticd.pid" % (self.dir, self.dir, self.dir))

    # Configure and start ospf6d for IPv6 emulation
    def start_ospf6d(self, **kwargs):
        # Zebra and Quagga config
        if len(self.nets) > 0:
            ospfd = open("%s/ospf6d.conf" % self.dir, 'w')
            ospfd.write("! -*- ospf6 -*-\n!\nhostname %s\n" % self.name)
            ospfd.write("password srv6\n"
                        "log file %s/ospf6d.log\n!\n" %
                        self.dir)
            # Iterate over the nets and build interface part of the configs
            for net in self.nets:
                # Link cost for the interface
                cost = net.get('cost', None)
                # Non-loopback interface
                if net['intf'] != 'lo':
                    if net['stub']:
                        # Stub network
                        # Set OSPF6 parameters and mark the network as
                        # passive in order to advertise the interface as
                        # a stub link
                        if cost is not None:
                            ospfd.write("interface %s\n"
                                        " ipv6 ospf6 passive\n"
                                        " ipv6 ospf6 cost %s\n"
                                        " ipv6 ospf6 hello-interval %s\n"
                                        " ipv6 ospf6 dead-interval %s\n"
                                        " ipv6 ospf6 retransmit-interval %s\n!\n"
                                        % (net['intf'], cost, HELLO_INTERVAL,
                                            DEAD_INTERVAL, RETRANSMIT_INTERVAL))
                        else:
                            ospfd.write("interface %s\n"
                                        " ipv6 ospf6 passive\n"
                                        " ipv6 ospf6 hello-interval %s\n"
                                        " ipv6 ospf6 dead-interval %s\n"
                                        " ipv6 ospf6 retransmit-interval %s\n!\n"
                                        % (net['intf'], HELLO_INTERVAL,
                                           DEAD_INTERVAL, RETRANSMIT_INTERVAL))
                    else:
                        # Transit network
                        if cost is not None:
                            ospfd.write("interface %s\n"
                                        " no ipv6 ospf6 passive\n"
                                        " ipv6 ospf6 cost %s\n"
                                        " ipv6 ospf6 hello-interval %s\n"
                                        " ipv6 ospf6 dead-interval %s\n"
                                        " ipv6 ospf6 retransmit-interval %s\n!\n"
                                        % (net['intf'], cost, HELLO_INTERVAL,
                                           DEAD_INTERVAL, RETRANSMIT_INTERVAL))
                        else:
                            ospfd.write("interface %s\n"
                                        " no ipv6 ospf6 passive\n"
                                        " ipv6 ospf6 hello-interval %s\n"
                                        " ipv6 ospf6 dead-interval %s\n"
                                        " ipv6 ospf6 retransmit-interval %s\n!\n"
                                        % (net['intf'], HELLO_INTERVAL,
                                           DEAD_INTERVAL, RETRANSMIT_INTERVAL))
            # Finishing ospf6d conf
            if kwargs.get('routerid', None):
                routerid = kwargs['routerid']
            ospfd.write("router ospf6\n"
                        " ospf6 router-id %s\n"
                        " redistribute static\n!\n" % routerid)
            ospfd.write(" area 0.0.0.0 range %s\n" % RANGE_FOR_AREA_0)
            # Iterate again over the nets to finish area part
            for net in self.nets:
                if net.get('is_private', False):
                    ospfd.write(" no interface %s area 0.0.0.0\n" % (net['intf']))
                else:
                    ospfd.write(" interface %s area 0.0.0.0\n" % (net['intf']))
            ospfd.write("!\n")
            ospfd.close()
            # Right permission and owners
            self.exec_cmd("chown frr /var/run")
            self.exec_cmd("chown frr %s/*.conf" % self.dir)
            self.exec_cmd("chown frr %s/." % self.dir)
            self.exec_cmd("chmod 640 %s/*.conf" % self.dir)
            self.exec_cmd("ospf6d -f %s/ospf6d.conf -d -z %s/zebra.sock -i "
                     "%s/ospf6d.pid" % (self.dir, self.dir, self.dir))

    # Configure and start zebra for IPv4 emulation
    def start_zebra_ipv4(self, **kwargs):
        # Zebra and Quagga config
        if len(self.nets) > 0:
            zebra = open("%s/zebra.conf" % self.dir, 'w')
            zebra.write("! -*- zebra -*-\n!\nhostname %s\n" %
                        self.name)
            zebra.write("password srv6\nenable password srv6\n"
                        "log file %s/zebra.log\n!\n" % self.dir)
            # Iterate over the nets and build interface part of the configs
            for net in self.nets:
                # Non-loopback interface
                if net['intf'] != 'lo':
                    # Set the IPv6 address and the network
                    # discovery prefix in the zebra configuration
                    zebra.write("interface %s\n"
                                " link-detect\n"
                                " bandwidth %s\n"
                                " ip address %s\n!\n"
                                % (net['intf'], min(net['bw']*1000, 100000), net['ip']))
            zebra.close()
            # Right permission and owners
            self.exec_cmd("chown frr /var/run")
            self.exec_cmd("chown frr %s/*.conf" % self.dir)
            self.exec_cmd("chown frr %s/." % self.dir)
            self.exec_cmd("chmod 640 %s/*.conf" % self.dir)
            self.start_time_zebra = datetime.now().replace(microsecond=0)
            # Start daemons
            self.exec_cmd("zebra -f %s/zebra.conf -d -z %s/zebra.sock -i "
                          "%s/zebra.pid" % (self.dir, self.dir, self.dir))


    # Configure and start ospfd for IPv4 emulation
    def start_ospfd(self, **kwargs):
        # Zebra and Quagga config
        if len(self.nets) > 0:
            ospfd = open("%s/ospfd.conf" % self.dir, 'w')
            ospfd.write("! -*- ospf -*-\n!\nhostname %s\n" % self.name)
            ospfd.write("password srv6\nlog file %s/ospfd.log\n!\n" %
                        self.dir)
            # Iterate over the nets and build interface part of the configs
            for net in self.nets:
                # Link cost for the interface
                cost = net.get('cost', None)
                # Non-loopback interface
                if net['intf'] != 'lo':
                    # Check if the interface is private
                    enable_ospf = 'no ' if net.get('is_private', False) else ''
                    if net['stub']:
                        # Stub network
                        # Set OSPF6 parameters and mark the network as
                        # passive in order to advertise the interface as
                        # a stub link
                        if cost is not None:
                            ospfd.write("interface %s\n"
                                        " %sip ospf area 0.0.0.0\n"
                                        " ip ospf cost %s\n"
                                        " ip ospf hello-interval %s\n"
                                        " ip ospf dead-interval %s\n"
                                        " ip ospf retransmit-interval %s\n!\n"
                                        % (net['intf'], enable_ospf, cost, HELLO_INTERVAL,
                                            DEAD_INTERVAL, RETRANSMIT_INTERVAL))
                        else:
                            ospfd.write("interface %s\n"
                                        " %sip ospf area 0.0.0.0\n"
                                        " ip ospf hello-interval %s\n"
                                        " ip ospf dead-interval %s\n"
                                        " ip ospf retransmit-interval %s\n!\n"
                                        % (net['intf'], enable_ospf, HELLO_INTERVAL,
                                           DEAD_INTERVAL, RETRANSMIT_INTERVAL))
                    else:
                        # Transit network
                        if cost is not None:
                            ospfd.write("interface %s\n"
                                        " %sip ospf area 0.0.0.0\n"
                                        " ip ospf cost %s\n"
                                        " ip ospf hello-interval %s\n"
                                        " ip ospf dead-interval %s\n"
                                        " ip ospf retransmit-interval %s\n!\n"
                                        % (net['intf'], enable_ospf, cost, HELLO_INTERVAL,
                                           DEAD_INTERVAL, RETRANSMIT_INTERVAL))
                        else:
                            ospfd.write("interface %s\n"
                                        " %sip ospf area 0.0.0.0\n"
                                        " ip ospf hello-interval %s\n"
                                        " ip ospf dead-interval %s\n"
                                        " ip ospf retransmit-interval %s\n!\n"
                                        % (net['intf'], enable_ospf, HELLO_INTERVAL,
                                           DEAD_INTERVAL, RETRANSMIT_INTERVAL))
            # Finishing ospf6d conf
            if kwargs.get('routerid', None):
                routerid = kwargs['routerid']
            ospfd.write("router ospf\n"
                        " ospf router-id %s\n"
                        " redistribute static\n!\n" % routerid)
            for net in self.nets:
                if net.get('stub', False):
                    ospfd.write(" passive-interface %s\n!\n" % net['intf'])
                else:
                    ospfd.write(" no passive-interface %s\n!\n" % net['intf'])
            ospfd.write("!\n")
            ospfd.close()
            # Right permission and owners
            self.exec_cmd("chown frr /var/run")
            self.exec_cmd("chown frr %s/*.conf" % self.dir)
            self.exec_cmd("chown frr %s/." % self.dir)
            self.exec_cmd("chmod 640 %s/*.conf" % self.dir)
            self.exec_cmd("ospfd -f %s/ospfd.conf -d -z %s/zebra.sock -i "
                     "%s/ospfd.pid" % (self.dir, self.dir, self.dir))

    # Clean up the environment
    def cleanup(self):

        Host.cleanup(self)
        # Rm dir
        if os.path.exists(self.dir):
            shutil.rmtree(self.dir)


# Abstraction to model a MHost
class MHost(Host):

    def __init__(self, name, *args, **kwargs):

        dirs = ['/var/mininet']
        Host.__init__(self, name, privateDirs=dirs, *args, **kwargs)
        self.dir = "/tmp/%s" % name
        self.nets = []
        if os.path.exists(self.dir):
            shutil.rmtree(self.dir)
        if not os.path.exists(self.dir):
            os.makedirs(self.dir)
        if kwargs.get('debug', False):
            self.exec_cmd = self.cmdPrint
        else:
            self.exec_cmd = self.cmd

    # Config hook
    def config(self, **kwargs):

        # Init steps
        Host.config(self, **kwargs)
        # Iterate over the interfaces
        for intf in self.intfs.values():
            # Remove any configured address
            self.exec_cmd('ip a flush dev %s scope global' % intf.name)
            # For the first one, let's configure the mgmt address
            if intf.name == kwargs.get('mgmtintf'):
                self.exec_cmd('ip a a %s dev %s' % (kwargs['mgmtip'], intf.name))
        # Let's write the hostname in /var/mininet/hostname
        self.exec_cmd("echo '" + self.name + "' > /var/mininet/hostname")
        # Let's write the hostname
        self.exec_cmd("echo 'HOSTNAME=%s' > %s/%s" % (self.name, self.dir, HOSTNAME_SH))
        # Let's write the id
        self.exec_cmd("echo 'DEVICEID='$(cat /proc/sys/kernel/random/uuid)'' > %s/%s" % (self.dir, DEVICEID_SH))
        # Let's write the neighbors
        if 'neighs' in kwargs:
            neighs_sh = '%s/%s' % (self.dir, NEIGHS_SH)
            with open(neighs_sh, 'w') as outfile:
                # Create header
                nodes = "declare -a NEIGHS=("
                # Iterate over management ips
                for neigh in kwargs['neighs']:
                    # Add the nodes one by one
                    nodes = nodes + "%s " % neigh
                if kwargs['neighs'] != []:
                    # Eliminate last character
                    nodes = nodes[:-1] + ")\n"
                else:
                    nodes = nodes + ")\n"
                # Write on the file
                outfile.write(nodes)
        # Let's write the interfaces
        if 'interfaces' in kwargs:
            interfaces_sh = '%s/%s' % (self.dir, INTERFACES_SH)
            with open(interfaces_sh, 'w') as outfile:
                # Create header
                nodes = "declare -A INTERFACES=("
                # Iterate over management ips
                for (neigh, intf) in kwargs['interfaces']:
                    # Add the nodes one by one
                    nodes = nodes + '[%s]=%s ' % (neigh, intf)
                if kwargs['interfaces'] != []:
                    # Eliminate last character
                    nodes = nodes[:-1] + ")\n"
                else:
                    nodes = nodes + ")\n"
                # Write on the file
                outfile.write(nodes)
        # Retrieve nets
        if kwargs.get('nets', None):
            self.nets = kwargs['nets']
        # If requested
        if kwargs['sshd']:
            # Let's start sshd daemon in the hosts
            self.exec_cmd('/usr/sbin/sshd -D &')
        # Disable IPv6 address autoconfiguration
        self.exec_cmd('sysctl -w net.ipv6.conf.all.autoconf=0')
        # Enable RA accept (stateless address autoconfiguration)
        self.exec_cmd('sysctl -w net.ipv6.conf.all.accept_ra=1')
        # Force Linux to keep all IPv6 addresses on an interface down event
        self.exec_cmd("sysctl -w net.ipv6.conf.all.keep_addr_on_down=1")
        # Iterate over the interfaces
        for intf in self.intfs.values():
            # Disable IPv6 address autoconfiguration on the interface
            # The addresses are configured by this script
            self.exec_cmd("sysctl -w net.ipv6.conf.%s.autoconf=0" % intf.name)
            # Accept Router Advertisements messages
            # Used to set a default via in the routing tables
            self.exec_cmd("sysctl -w net.ipv6.conf.%s.accept_ra=1" % intf.name)
            # Force Linux to keep all IPv6 addresses on an interface down event
            self.exec_cmd("sysctl -w net.ipv6.conf.%s.keep_addr_on_down=1"
                          % intf.name)
        for net in self.nets:
            # Set the address
            self.exec_cmd('ip a a %s dev %s' % (net['ip'], net['intf']))
        # Configure the default via
        default_via = kwargs.get('default_via', None)
        if default_via is not None:
            self.exec_cmd('ip r d default')
            self.exec_cmd('ip -6 r d default')
            self.exec_cmd('ip r a default via %s' % default_via)
        # Configure the routes
        if kwargs.get('routes', None):
            for route in kwargs['routes']:
                dest = route['dest']
                via = route['via']
                self.exec_cmd("ip route add %s via %s\n"  % (dest, via))
        # Run scripts
        self.exec_cmd('export PATH=%s:$PATH' % os.path.dirname(PYTHON_PATH))
        if 'scripts' in kwargs:
            for script in kwargs['scripts']:
                script_path = os.path.abspath(os.path.join('scripts', script))
                self.exec_cmd('cd %s' % self.dir)
                self.exec_cmd('bash %s &' % script_path)
        # Let's write the interfaces
        if 'nodes' in kwargs:
            nodes_sh = '%s/%s' % (self.dir, NODES_SH)
            with open(nodes_sh, 'w') as outfile:
                # Create header
                nodes = "declare -A NODES=("
                # Iterate over management ips
                for node, ip in kwargs['nodes'].items():
                    # Add the nodes one by one
                    nodes = nodes + '[%s]=%s ' % (node, ip)
                if kwargs['nodes'] != []:
                    # Eliminate last character
                    nodes = nodes[:-1] + ")\n"
                else:
                    nodes = nodes + ")\n"
                # Write on the file
                outfile.write(nodes)


# Abstraction to model a SRv6Controller
class SRv6Controller(MHost):

    # Config hook
    def config(self, **kwargs):

        MHost.config(self, **kwargs)
        # Configure the loopback address
        if kwargs.get('loopbackip', None):
            self.exec_cmd('ip a a %s dev lo' % (kwargs['loopbackip']))
            self.nets.append({
              'intf': 'lo',
              'ip': kwargs['loopbackip'],
              'net': kwargs['loopbackip']})


# Abstraction to model a SRv6Firewall
class WANRouter(MHost):

    # Config hook
    def config(self, **kwargs):

        MHost.config(self, **kwargs)
        script = kwargs.get('script')
        if script is not None:
            pass
        # Enable IPv6 forwarding
        self.exec_cmd("sysctl -w net.ipv6.conf.all.forwarding=1")
        # Enable IPv4 forwarding
        self.exec_cmd("sysctl -w net.ipv4.conf.all.forwarding=1")
        # Configure the loopback address
        if kwargs.get('loopbackip', None):
            self.exec_cmd('ip a a %s dev lo' % (kwargs['loopbackip']))
            self.nets.append({
              'intf': 'lo',
              'ip': kwargs['loopbackip'],
              'net': kwargs['loopbackip']})
