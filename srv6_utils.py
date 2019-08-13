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

from srv6_generators import RANGE_FOR_AREA_0

# Mininet
from mininet.node import Host
from mininet.log import error

# General imports
import os
import shutil
import time
import sys

# Path to the southbound gRPC-based server
DATA_PLANE_FOLDER = '../srv6-sdn-data-plane'
SB_GRPC_SERVER_PATH = '%s/southbound/grpc/sb_grpc_server.py' % DATA_PLANE_FOLDER

if DATA_PLANE_FOLDER == '':
    print 'Error: Set DATA_PLANE_FOLDER variable in srv6_utils.py'
    sys.exist(-2)

if not os.path.exists(DATA_PLANE_FOLDER):
    error('Error: DATA_PLANE_FOLDER variable in srv6_utils.py points to a non existing folder\n')
    sys.exist(-2)

# This workaround solves the issue of python commands
# executed outside the virtual environment
PYTHON_PATH = sys.executable


# Abstraction to model a SRv6Router
class SRv6Router(Host):

    def __init__(self, name, *args, **kwargs):

        dirs = ['/var/mininet']
        Host.__init__(self, name, privateDirs=dirs, *args, **kwargs)
        self.dir = "/tmp/%s" % name
        self.nets = []
        if not os.path.exists(self.dir):
            os.makedirs(self.dir)

    # Config hook
    def config(self, **kwargs):

        # Init steps
        Host.config(self, **kwargs)
        # Iterate over the interfaces
        first = True
        for intf in self.intfs.itervalues():
            # Remove any configured address
            self.cmd('ifconfig %s 0' % intf.name)
            # For the first one, let's configure the mgmt address
            if first:
                first = False
                self.cmd('ip a a %s dev %s' % (kwargs['mgmtip'], intf.name))
        # Let's write the hostname in /var/mininet/hostname
        self.cmd("echo '" + self.name + "' > /var/mininet/hostname")
        # Retrieve nets
        if kwargs.get('nets', None):
            self.nets = kwargs['nets']
        # If requested
        if kwargs['sshd']:
            # Let's start sshd daemon in the hosts
            self.cmd('/usr/sbin/sshd -D &')
        # Configure the loopback address
        if kwargs.get('loopbackip', None):
            self.cmd('ip a a %s dev lo' % (kwargs['loopbackip']))
            self.nets.append({
              'intf': 'lo',
              'ip': kwargs['loopbackip'],
              'net': kwargs['loopbackip']})
        # Enable IPv6 forwarding
        self.cmd("sysctl -w net.ipv6.conf.all.forwarding=1")
        # Enable IPv4 forwarding
        self.cmd("sysctl -w net.ipv4.conf.all.forwarding=1")
        # Disable rp filter
        self.cmd("sysctl -w net.ipv4.conf.all.rp_filter=0")
        # Enable SRv6 on the interface
        self.cmd("sysctl -w net.ipv6.conf.all.seg6_enabled=1")
        # Disable RA accept
        self.cmd("sysctl -w net.ipv6.conf.all.accept_ra=0")
        # Force Linux to keep all IPv6 addresses on an interface down event
        self.cmd("echo 1 > /proc/sys/net/ipv6/conf/all/keep_addr_on_down")
        # Iterate over the interfaces
        for intf in self.intfs.itervalues():
            # Force Linux to keep all IPv6 addresses on an interface down event
            self.cmd("sysctl -w net.ipv6.conf.%s.keep_addr_on_down=1")
            # Enable IPv6 forwarding
            self.cmd("sysctl -w net.ipv6.conf.%s.forwarding=1" % intf.name)
            # Enable SRv6 on the interface
            self.cmd("sysctl -w net.ipv6.conf.%s.seg6_enabled=1" % intf.name)
            # Enable IPv4 forwarding
            self.cmd("sysctl -w net.ipv4.conf.%s.forwarding=1" % intf.name)
            # Disable rp filter
            self.cmd("sysctl -w net.ipv4.conf.%s.rp_filter=0" % intf.name)
        # Zebra and Quagga config
        if len(self.nets) > 0:
            zebra = open("%s/zebra.conf" % self.dir, 'w')
            ospfd = open("%s/ospf6d.conf" % self.dir, 'w')
            ospfd.write("! -*- ospf6 -*-\n!\nhostname %s\n" % self.name)
            ospfd.write("password srv6\nlog file %s/ospf6d.log\n!\n" %
                        self.dir)
            zebra.write("! -*- zebra -*-\n!\nhostname %s\n" %
                        self.name)
            zebra.write("password srv6\nenable password srv6\n"
                        "log file %s/zebra.log\n!\n" % self.dir)
            # Add static route for router network
            if kwargs.get('routernet', None):
                routernet = kwargs['routernet']
                zebra.write("ipv6 route %s lo\n!\n" % routernet)
            # Iterate over the nets and build interface part of the configs
            for net in self.nets:
                cost = 1698
                ra_interval = 10
                # To mitigate annoying warnings
                if net['intf'] == 'lo':
                    ospfd.write("interface %s\n!ipv6 ospf6 cost %s\n"
                                "ipv6 ospf6 hello-interval %s\n!\n" %
                                (net['intf'], cost, 600))
                else:
                    if net['stub']:
                        # Stub network
                        ospfd.write("interface %s\nipv6 ospf6 passive\n"
                                    "ipv6 ospf6 cost %s\n"
                                    "ipv6 ospf6 hello-interval %s\n"
                                    "ipv6 ospf6 dead-interval 3\n"
                                    "ipv6 ospf6 retransmit-interval 3\n!\n"
                                    % (net['intf'], cost, 1))
                        if net.get('mgmt', False) is False:
                            # Set the IPv6 address
                            # and the network discovery prefix
                            # in the zebra configuration
                            zebra.write("interface %s\nlink-detect\n"
                                        "no ipv6 nd suppress-ra\n"
                                        "ipv6 nd ra-interval %s\n"
                                        "ipv6 address %s\n"
                                        "ipv6 nd prefix %s\n!\n"
                                        % (net['intf'], ra_interval,
                                           net['ip'], net['net']))
                    else:
                        # Transit network
                        ospfd.write("interface %s\nipv6 ospf6 cost %s\n"
                                    "ipv6 ospf6 hello-interval %s\n"
                                    "ipv6 ospf6 dead-interval 3\n"
                                    "ipv6 ospf6 retransmit-interval 3\n!\n"
                                    % (net['intf'], cost, 1))
                        if net.get('mgmt', False) is False:
                            # Both in IPv4 and IPv6 emulation
                            # transit networks use IPv6 addresses
                            # Set the IPv6 address and the network
                            # discovery prefix in the zebra configuration
                            zebra.write("interface %s\nlink-detect\n"
                                        "no ipv6 nd suppress-ra\n"
                                        "ipv6 nd ra-interval %s\n"
                                        "ipv6 address %s\n"
                                        "ipv6 nd prefix %s\n!\n"
                                        % (net['intf'], ra_interval,
                                           net['ip'], net['net']))
                        else:
                            # Both in IPv4 and IPv6 emulation
                            # transit networks use IPv6 addresses
                            # Set the IPv6 address and the network
                            # discovery prefix in the zebra configuration
                            zebra.write("interface %s\nlink-detect\n"
                                        "no ipv6 nd suppress-ra\n"
                                        "ipv6 nd ra-interval %s\n"
                                        "ipv6 address %s\n"
                                        "ipv6 nd prefix %s\n!\n"
                                        % (net['intf'], ra_interval,
                                           net['ip'], net['net']))
            # Finishing ospf6d conf
            if kwargs.get('routerid', None):
                routerid = kwargs['routerid']
            ospfd.write("router ospf6\nrouter-id %s\n "
                        "redistribute static\n!\n" % routerid)
            ospfd.write("area 0.0.0.0 range %s\n" % RANGE_FOR_AREA_0)
            # Iterate again over the nets to finish area part
            for net in self.nets:
                #if net.get('mgmt', False) is True:
                ospfd.write("interface %s area 0.0.0.0\n" % (net['intf']))
            ospfd.write("!\n")
            ospfd.close()
            zebra.close()
            # Right permission and owners
            self.cmd("chown quagga.quaggavty %s/*.conf" % self.dir)
            self.cmd("chown quagga.quaggavty %s/." % self.dir)
            self.cmd("chown quagga %s/*.conf" % self.dir)
            self.cmd("chown quagga %s/." % self.dir)
            self.cmd("chmod 640 %s/*.conf" % self.dir)
            # Starting daemons
            self.cmd("zebra -f %s/zebra.conf -d -z %s/zebra.sock -i "
                     "%s/zebra.pid" % (self.dir, self.dir, self.dir))
            # In some systems this workaround solves the issue
            # of ospf6d coming up before zebra
            time.sleep(.001)
            self.cmdPrint("ospf6d -f %s/ospf6d.conf -d -z %s/zebra.sock -i "
                     "%s/ospf6d.pid" % (self.dir, self.dir, self.dir))
            # Starting gRPC server
            self.cmd("%s %s &" % (PYTHON_PATH, SB_GRPC_SERVER_PATH))

    # Clean up the environment
    def cleanup(self):

        Host.cleanup(self)
        # Rm dir
        if os.path.exists(self.dir):
            shutil.rmtree(self.dir)


class MHost(Host):

    def __init__(self, name, *args, **kwargs):

        dirs = ['/var/mininet']
        Host.__init__(self, name, privateDirs=dirs, *args, **kwargs)
        self.dir = "/tmp/%s" % name
        self.nets = []
        if not os.path.exists(self.dir):
            os.makedirs(self.dir)

    # Config hook
    def config(self, **kwargs):

        # Init steps
        Host.config(self, **kwargs)
        # Disable IPv6 address autoconfiguration
        self.cmd('sysctl -w net.ipv6.conf.all.autoconf=0')
        self.cmd('sysctl -w net.ipv6.conf.all.accept_ra=1')
        # Iterate over the interfaces
        first = True
        for intf in self.intfs.itervalues():
            # Disable IPv6 address autoconfiguration on the interface
            # The addresses are configured by this script
            self.cmd("sysctl -w net.ipv6.conf.%s.autoconf=0" % intf.name)
            # Accept Router Advertisements messages
            # Used to set a default via in the routing tables
            self.cmd("sysctl -w net.ipv6.conf.%s.accept_ra=1" % intf.name)
            # Remove any configured address
            self.cmd('ip a flush dev %s scope global' % intf.name)
            # For the first one, let's configure the mgmt address
            if first:
                first = False
                self.cmd('ip a a %s dev %s' % (kwargs['mgmtip'], intf.name))
        # Let's write the hostname in /var/mininet/hostname
        self.cmd("echo '" + self.name + "' > /var/mininet/hostname")
        # Retrieve nets
        if kwargs.get('nets', None):
            self.nets = kwargs['nets']
        # If requested
        if kwargs['sshd']:
            # Let's start sshd daemon in the hosts
            self.cmd('/usr/sbin/sshd -D &')
        for net in self.nets:
            # Set the address
            self.cmd('ip a a %s dev %s' % (net['ip'], net['intf']))
        # Force Linux to keep all IPv6 addresses on an interface down event
        self.cmd("echo 1 > /proc/sys/net/ipv6/conf/all/keep_addr_on_down")

    # Clean up the environment
    def cleanup(self):

        Host.cleanup(self)
        # Rm dir
        if os.path.exists(self.dir):
            shutil.rmtree(self.dir)


class SRv6Controller(Host):

    def __init__(self, name, *args, **kwargs):

        dirs = ['/var/mininet']
        Host.__init__(self, name, privateDirs=dirs, *args, **kwargs)
        self.dir = "/tmp/%s" % name
        self.nets = []
        if not os.path.exists(self.dir):
            os.makedirs(self.dir)

    # Config hook
    def config(self, **kwargs):

        # Init steps
        Host.config(self, **kwargs)
        # Iterate over the interfaces
        first = True
        for intf in self.intfs.itervalues():
            # Remove any configured address
            self.cmd('ifconfig %s 0' % intf.name)
            # For the first one, let's configure the mgmt address
            if first:
                first = False
                self.cmd('ip a a %s dev %s' % (kwargs['mgmtip'], intf.name))
        # Let's write the hostname in /var/mininet/hostname
        self.cmd("echo '" + self.name + "' > /var/mininet/hostname")
        # Retrieve nets
        if kwargs.get('nets', None):
            self.nets = kwargs['nets']
        # If requested
        if kwargs['sshd']:
            # Let's start sshd daemon in the hosts
            self.cmd('/usr/sbin/sshd -D &')
        # Configure the loopback address
        if kwargs.get('loopbackip', None):
            self.cmd('ip a a %s dev lo' % (kwargs['loopbackip']))
            self.nets.append({'intf': 'lo', 'ip': kwargs['loopbackip'],
                             'net': kwargs['loopbackip']})
        # Enable IPv6 forwarding
        self.cmd("sysctl -w net.ipv6.conf.all.forwarding=1")
        # Enable SRv6 on the interface
        self.cmd("sysctl -w net.ipv6.conf.all.seg6_enabled=1")
        # Disable RA accept
        self.cmd("sysctl -w net.ipv6.conf.all.accept_ra=1")
        # Force Linux to keep all IPv6 addresses on an interface down event
        self.cmd("echo 1 > /proc/sys/net/ipv6/conf/all/keep_addr_on_down")
        # Iterate over the interfaces
        for intf in self.intfs.itervalues():
            # Force Linux to keep all IPv6 addresses on an interface down event
            self.cmd("sysctl -w net.ipv6.conf.%s.keep_addr_on_down=1")
            # Enable IPv6 forwarding
            self.cmd("sysctl -w net.ipv6.conf.%s.forwarding=1" % intf.name)
            # Enable SRv6 on the interface
            self.cmd("sysctl -w net.ipv6.conf.%s.seg6_enabled=1" % intf.name)
        # Zebra and Quagga config
        if len(self.nets) > 0:
            zebra = open("%s/zebra.conf" % self.dir, 'w')
            ospfd = open("%s/ospf6d.conf" % self.dir, 'w')
            ospfd.write("! -*- ospf6 -*-\n!\nhostname %s\n" % self.name)
            ospfd.write("password srv6\nlog file %s/ospf6d.log\n!\n" %
                        self.dir)
            zebra.write("! -*- zebra -*-\n!\nhostname %s\n" % self.name)
            zebra.write("password srv6\nenable password srv6\n"
                        "log file %s/zebra.log\n!\n" % self.dir)
            # Iterate over the nets and build interface part of the configs
            for net in self.nets:
                cost = 1
                # To mitigate annoying warnings
                if net['intf'] == 'lo':
                    ospfd.write("interface %s\n!ipv6 ospf6 cost %s\n"
                                "ipv6 ospf6 hello-interval %s\n!\n"
                                % (net['intf'], cost, 600))
                else:
                    if net['stub']:
                        # Mark the link as stub
                        ospfd.write("interface %s\nipv6 ospf6 passive\n"
                                    "ipv6 ospf6 cost %s\n"
                                    "ipv6 ospf6 hello-interval %s\n"
                                    "ipv6 ospf6 dead-interval 3\n"
                                    "ipv6 ospf6 retransmit-interval 3\n!\n"
                                    % (net['intf'], cost, 1))
                    else:
                        ospfd.write("interface %s\nipv6 ospf6 cost %s\n"
                                    "ipv6 ospf6 hello-interval %s\n"
                                    "ipv6 ospf6 dead-interval 3\n"
                                    "ipv6 ospf6 retransmit-interval 3\n!\n"
                                    % (net['intf'], cost, 1))
                        if net.get('mgmt', False) is True:
                            # Both in IPv4 and IPv6 emulation
                            # transit networks use IPv6 addresses
                            # Set the IPv6 address and the network
                            # discovery prefix in the zebra configuration
                            zebra.write("interface %s\nlink-detect\n"
                                        "ipv6 address %s\n"
                                        "ipv6 nd prefix %s\n!\n"
                                        % (net['intf'],
                                           net['ip'], net['net']))
            # Finishing ospf6d conf
            if kwargs.get('routerid', None):
                routerid = kwargs['routerid']
            ospfd.write("router ospf6\nrouter-id %s\n"
                        "no redistribute static\nno redistribute connected\n"
                        "no redistribute kernel\n!\n" % routerid)
            ospfd.write("area 0.0.0.0 range %s\n" % RANGE_FOR_AREA_0)
            # Iterate again over the nets to finish area part
            for net in self.nets:
                ospfd.write("interface %s area 0.0.0.0\n" % (net['intf']))
            ospfd.write("!\n")
            ospfd.close()
            zebra.close()
            # Right permission and owners
            self.cmd("chown quagga.quaggavty %s/*.conf" % self.dir)
            self.cmd("chown quagga.quaggavty %s/." % self.dir)
            self.cmd("chown quagga %s/*.conf" % self.dir)
            self.cmd("chown quagga %s/." % self.dir)
            self.cmd("chmod 640 %s/*.conf" % self.dir)
            # Starting daemons
            self.cmd("zebra -f %s/zebra.conf -d -z %s/zebra.sock -i "
                     "%s/zebra.pid" % (self.dir, self.dir, self.dir))
            # In some systems this workaround solves
            # the issue of ospf6d coming up before zebra
            time.sleep(.001)
            self.cmd("ospf6d -f %s/ospf6d.conf -d -z %s/zebra.sock -i "
                     "%s/ospf6d.pid" % (self.dir, self.dir, self.dir))

    # Clean up the environment
    def cleanup(self):

        Host.cleanup(self)
        # Rm dir
        if os.path.exists(self.dir):
            shutil.rmtree(self.dir)
