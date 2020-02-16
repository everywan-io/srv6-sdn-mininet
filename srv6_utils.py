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


# General imports
from __future__ import absolute_import, division, print_function
import os
import shutil
import sys
import random
# Mininet dependencies
from mininet.node import Host
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

# Filenames of the bash scripts
#
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
# ips.sh file containing the ips
IPS_SH = 'ips.sh'

# Initialize random seed
random.seed(0)


# Generate a random UUID used to identify the node
def generate_uuid():
    # Example of UUID: 7a0525c1-22e9-cc50-d44d-5149c7524f1f
    global seed_initiated
    seq = 'abcdef1234567890'
    uuid = ''
    # First block
    for _ in range(0, 8):
        uuid += random.choice(seq)
    uuid += '-'
    # Second block
    for _ in range(0, 4):
        uuid += random.choice(seq)
    uuid += '-'
    # Third block
    for _ in range(0, 4):
        uuid += random.choice(seq)
    uuid += '-'
    # Fourth block
    for _ in range(0, 4):
        uuid += random.choice(seq)
    uuid += '-'
    # Fifth block
    for _ in range(0, 12):
        uuid += random.choice(seq)
    # Return the UUID
    return uuid


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
        self.exec_cmd("for session in $(screen -ls | grep -o '[0-9]*\.%s'); do screen -S ${session} -X quit; done" % self.name)

    # Config hook
    def config(self, **kwargs):

        # Init steps
        Host.config(self, **kwargs)
        # Iterate over the interfaces
        for intf in self.intfs.values():
            # Remove any configured address
            self.exec_cmd('ifconfig %s 0' % intf.name)
        # Let's write the hostname in /var/mininet/hostname
        self.exec_cmd("echo '" + self.name + "' > /var/mininet/hostname")
        # Let's write the hostname
        self.exec_cmd("echo 'HOSTNAME=%s' > %s/%s" %
                      (self.name, self.dir, HOSTNAME_SH))
        # Let's write the id
        uuid = generate_uuid()
        self.exec_cmd("echo 'DEVICEID=%s' > %s/%s" %
                      (uuid, self.dir, DEVICEID_SH))
        # Let's write the neighbors
        if kwargs.get('neighs', None) is not None:
            neighs_sh = '%s/%s' % (self.dir, NEIGHS_SH)
            with open(neighs_sh, 'w') as outfile:
                # Create header
                neighs = "declare -a NEIGHS=("
                # Iterate over neighbor ips
                for neigh in kwargs['neighs']:
                    # Add the neighs one by one
                    neighs = neighs + "%s " % neigh
                if kwargs['neighs'] != []:
                    # Eliminate last character
                    neighs = neighs[:-1] + ")\n"
                else:
                    neighs = neighs + ")\n"
                # Write on the file
                outfile.write(neighs)
        # Let's write the interfaces
        if kwargs.get('interfaces', None) is not None:
            interfaces_sh = '%s/%s' % (self.dir, INTERFACES_SH)
            with open(interfaces_sh, 'w') as outfile:
                # Create header
                interfaces = "declare -A INTERFACES=("
                # Iterate over interfaces
                for (neigh, intf) in kwargs['interfaces']:
                    # Add the interfaces one by one
                    interfaces = interfaces + '[%s]=%s ' % (neigh, intf)
                if kwargs['interfaces'] != []:
                    # Eliminate last character
                    interfaces = interfaces[:-1] + ")\n"
                else:
                    interfaces = interfaces + ")\n"
                # Write on the file
                outfile.write(interfaces)
        # Retrieve nets
        self.nets = list()
        if kwargs.get('nets', None) is not None:
            self.nets = kwargs['nets']
        # If requested
        if kwargs.get('sshd', False):
            # Let's start sshd daemon in the hosts
            self.exec_cmd('/usr/sbin/sshd -D &')
        # Configure the loopback address
        if kwargs.get('loopbackip', None) is not None:
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
            self.exec_cmd(
                "sysctl -w net.ipv6.conf.%s.forwarding=1" % intf.name)
            # Enable IPv4 forwarding
            self.exec_cmd(
                "sysctl -w net.ipv4.conf.%s.forwarding=1" % intf.name)
            # Disable Reverse Path Forwarding filter
            self.exec_cmd("sysctl -w net.ipv4.conf.%s.rp_filter=0" % intf.name)
            # Enable SRv6 on the interface
            self.exec_cmd(
                "sysctl -w net.ipv6.conf.%s.seg6_enabled=1" % intf.name)
            # Disable RA accept (stateless address autoconfiguration)
            self.exec_cmd("sysctl -w net.ipv6.conf.%s.accept_ra=0" % intf.name)
            # Force Linux to keep all IPv6 addresses on an interface down event
            self.exec_cmd(
                "sysctl -w net.ipv6.conf.%s.keep_addr_on_down=1" % intf.name)
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
        # Let's write the interfaces
        if kwargs.get('nodes', None) is not None:
            nodes_sh = '%s/%s' % (self.dir, NODES_SH)
            with open(nodes_sh, 'w') as outfile:
                # Create header
                nodes = "declare -A NODES=("
                # Iterate over nodes
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
        # Let's write the ips
        ips_sh = '%s/%s' % (self.dir, IPS_SH)
        with open(ips_sh, 'w') as outfile:
            # Create header
            ips = "declare -A IPS=("
            # Iterate over ips
            for net in self.nets:
                # Add the ips one by one
                ip = net['ip'].split('/')[0]
                ips = ips + '[%s]=%s ' % (net['intf'], ip)
            if self.nets != []:
                # Eliminate last character
                ips = ips[:-1] + ")\n"
            else:
                ips = ips + ")\n"
            # Write on the file
            outfile.write(ips)
        # Add python path to PATH environment variable
        # This solves the issue of python commands executed
        # outside the virtual environment
        self.exec_cmd('export PATH=%s:$PATH' % os.path.dirname(PYTHON_PATH))
        self.exec_cmd('export SCREENDIR=/run/screen/S-%s' % self.name)
        # Run scripts
        scripts = ''
        for script in kwargs.get('scripts', []):
            # Change directory to the host dir
            self.exec_cmd('cd %s' % self.dir)
            # Get full path
            script_path = os.path.abspath(os.path.join('scripts', script))
            # Append the script to the scripts
            scripts += script_path + ' & '
        if scripts != '':
            # This line forces screen to keep opened
            # after the scripts termination
            scripts = scripts[:-3] + '; exec bash'
            # Execute the scripts
            self.exec_cmd("screen -dmS %s bash -c '%s'" % (self.name, scripts))

    # Configure and start zebra for IPv6 emulation
    def start_zebra_ipv6(self, **kwargs):
        # Zebra and FRR config
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
                                % (net['intf'], min(net['bw']*1000, 100000),
                                   RA_INTERVAL, net['ip'], net['net']))
            zebra.close()
            # Right permission and owners
            self.exec_cmd("chown frr /var/run")
            self.exec_cmd("chown frr %s/*.conf" % self.dir)
            self.exec_cmd("chown frr %s/." % self.dir)
            self.exec_cmd("chmod 640 %s/*.conf" % self.dir)
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
            staticd.write("ip route %s %s\n" % ('0.0.0.0/0', default_via))
        # Configure the routes
        if kwargs.get('routes', None):
            for route in kwargs['routes']:
                dest = route['dest']
                via = route['via']
                staticd.write("ip route %s %s\n" % (dest, via))
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
            staticd.write("ipv6 route %s %s\n" % ('::/0', default_via))
        # Add static route for router network
        if kwargs.get('routernet', None):
            routernet = kwargs['routernet']
            staticd.write("ipv6 route %s lo\n!\n" % routernet)
        # Configure the routes
        if kwargs.get('routes', None):
            for route in kwargs['routes']:
                dest = route['dest']
                via = route['via']
                staticd.write("ipv6 route %s %s\n" % (dest, via))
        staticd.close()
        self.exec_cmd("chown frr /var/run")
        self.exec_cmd("chown frr %s/*.conf" % self.dir)
        self.exec_cmd("chown frr %s/." % self.dir)
        self.exec_cmd("chmod 640 %s/*.conf" % self.dir)
        # Start zebra daemon
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
                                        " ipv6 ospf6 retransmit-interval %s\n"
                                        "!\n"
                                        % (net['intf'], cost, HELLO_INTERVAL,
                                           DEAD_INTERVAL, RETRANSMIT_INTERVAL))
                        else:
                            ospfd.write("interface %s\n"
                                        " ipv6 ospf6 passive\n"
                                        " ipv6 ospf6 hello-interval %s\n"
                                        " ipv6 ospf6 dead-interval %s\n"
                                        " ipv6 ospf6 retransmit-interval %s\n"
                                        "!\n"
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
                                        " ipv6 ospf6 retransmit-interval %s\n"
                                        "!\n"
                                        % (net['intf'], cost, HELLO_INTERVAL,
                                           DEAD_INTERVAL, RETRANSMIT_INTERVAL))
                        else:
                            ospfd.write("interface %s\n"
                                        " no ipv6 ospf6 passive\n"
                                        " ipv6 ospf6 hello-interval %s\n"
                                        " ipv6 ospf6 dead-interval %s\n"
                                        " ipv6 ospf6 retransmit-interval %s\n"
                                        "!\n"
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
                    ospfd.write(" no interface %s area 0.0.0.0\n" %
                                (net['intf']))
                else:
                    ospfd.write(" interface %s area 0.0.0.0\n" % (net['intf']))
            ospfd.write("!\n")
            ospfd.close()
            # Right permission and owners
            self.exec_cmd("chown frr /var/run")
            self.exec_cmd("chown frr %s/*.conf" % self.dir)
            self.exec_cmd("chown frr %s/." % self.dir)
            self.exec_cmd("chmod 640 %s/*.conf" % self.dir)
            # Start ospf6d daemon
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
                                % (net['intf'], min(net['bw']*1000, 100000),
                                   net['ip']))
            zebra.close()
            # Right permission and owners
            self.exec_cmd("chown frr /var/run")
            self.exec_cmd("chown frr %s/*.conf" % self.dir)
            self.exec_cmd("chown frr %s/." % self.dir)
            self.exec_cmd("chmod 640 %s/*.conf" % self.dir)
            # Start zebra daemon
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
                                        " ip ospf retransmit-interval %s\n"
                                        "!\n"
                                        % (net['intf'], enable_ospf, cost,
                                           HELLO_INTERVAL, DEAD_INTERVAL,
                                           RETRANSMIT_INTERVAL))
                        else:
                            ospfd.write("interface %s\n"
                                        " %sip ospf area 0.0.0.0\n"
                                        " ip ospf hello-interval %s\n"
                                        " ip ospf dead-interval %s\n"
                                        " ip ospf retransmit-interval %s\n"
                                        "!\n"
                                        % (net['intf'], enable_ospf,
                                           HELLO_INTERVAL, DEAD_INTERVAL,
                                           RETRANSMIT_INTERVAL))
                    else:
                        # Transit network
                        if cost is not None:
                            ospfd.write("interface %s\n"
                                        " %sip ospf area 0.0.0.0\n"
                                        " ip ospf cost %s\n"
                                        " ip ospf hello-interval %s\n"
                                        " ip ospf dead-interval %s\n"
                                        " ip ospf retransmit-interval %s\n"
                                        "!\n"
                                        % (net['intf'], enable_ospf, cost,
                                           HELLO_INTERVAL, DEAD_INTERVAL,
                                           RETRANSMIT_INTERVAL))
                        else:
                            ospfd.write("interface %s\n"
                                        " %sip ospf area 0.0.0.0\n"
                                        " ip ospf hello-interval %s\n"
                                        " ip ospf dead-interval %s\n"
                                        " ip ospf retransmit-interval %s\n"
                                        "!\n"
                                        % (net['intf'], enable_ospf,
                                           HELLO_INTERVAL, DEAD_INTERVAL,
                                           RETRANSMIT_INTERVAL))
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
            # Start ospfd daemon
            self.exec_cmd("ospfd -f %s/ospfd.conf -d -z %s/zebra.sock -i "
                          "%s/ospfd.pid" % (self.dir, self.dir, self.dir))

    # Terminate node
    def terminate(self):
        # Stop screen session
        #self.exec_cmd('screen -XS %s quit' % self.name)
        self.exec_cmd("for session in $(screen -ls | grep -o '[0-9]*\.%s'); do screen -S ${session} -X quit; done" % self.name)
        Host.terminate(self)

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
        self.exec_cmd("for session in $(screen -ls | grep -o '[0-9]*\.%s'); do screen -S ${session} -X quit; done" % self.name)

    # Config hook
    def config(self, **kwargs):

        # Init steps
        Host.config(self, **kwargs)
        # Iterate over the interfaces
        for intf in self.intfs.values():
            # Remove any configured address
            self.exec_cmd('ip a flush dev %s scope global' % intf.name)
        # Let's write the hostname in /var/mininet/hostname
        self.exec_cmd("echo '" + self.name + "' > /var/mininet/hostname")
        # Let's write the hostname
        self.exec_cmd("echo 'HOSTNAME=%s' > %s/%s" %
                      (self.name, self.dir, HOSTNAME_SH))
        # Let's write the id
        uuid = generate_uuid()
        self.exec_cmd("echo 'DEVICEID=%s' > %s/%s" %
                      (uuid, self.dir, DEVICEID_SH))
        # Let's write the neighbors
        if kwargs.get('neighs', None) is not None:
            neighs_sh = '%s/%s' % (self.dir, NEIGHS_SH)
            with open(neighs_sh, 'w') as outfile:
                # Create header
                neighs = "declare -a NEIGHS=("
                # Iterate over neighbors
                for neigh in kwargs['neighs']:
                    # Add the neighs one by one
                    neighs = neighs + "%s " % neigh
                if kwargs['neighs'] != []:
                    # Eliminate last character
                    neighs = neighs[:-1] + ")\n"
                else:
                    neighs = neighs + ")\n"
                # Write on the file
                outfile.write(neighs)
        # Let's write the interfaces
        if kwargs.get('interfaces', None) is not None:
            interfaces_sh = '%s/%s' % (self.dir, INTERFACES_SH)
            with open(interfaces_sh, 'w') as outfile:
                # Create header
                interfaces = "declare -A INTERFACES=("
                # Iterate over interfaces
                for (neigh, intf) in kwargs['interfaces']:
                    # Add the interfaces one by one
                    interfaces = interfaces + '[%s]=%s ' % (neigh, intf)
                if kwargs['interfaces'] != []:
                    # Eliminate last character
                    interfaces = interfaces[:-1] + ")\n"
                else:
                    interfaces = interfaces + ")\n"
                # Write on the file
                outfile.write(interfaces)
        # Let's write the ips
        ips_sh = '%s/%s' % (self.dir, IPS_SH)
        with open(ips_sh, 'w') as outfile:
            # Create header
            ips = "declare -A IPS=("
            # Iterate over ips
            for net in self.nets:
                # Add the ips one by one
                ip = net['ip'].split('/')[0]
                ips = ips + '[%s]=%s ' % (net['intf'], ip)
            if self.nets != []:
                # Eliminate last character
                ips = ips[:-1] + ")\n"
            else:
                ips = ips + ")\n"
            # Write on the file
            outfile.write(ips)
        # Retrieve nets
        self.nets = list()
        if kwargs.get('nets', None) is not None:
            self.nets = kwargs['nets']
        # If requested
        if kwargs.get('sshd', False):
            # Let's start sshd daemon in the hosts
            self.exec_cmd('/usr/sbin/sshd -D &')
        # Configure the loopback address
        if kwargs.get('loopbackip', None) is not None:
            self.exec_cmd('ip a a %s dev lo' % (kwargs['loopbackip']))
            self.nets.append({
                'intf': 'lo',
                'ip': kwargs['loopbackip'],
                'net': kwargs['loopbackip']})
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
        for route in kwargs.get('routes', []):
            dest = route['dest']
            via = route['via']
            self.exec_cmd("ip route add %s via %s\n" % (dest, via))
        # Let's write the interfaces
        if kwargs.get('nodes', None) is not None:
            nodes_sh = '%s/%s' % (self.dir, NODES_SH)
            with open(nodes_sh, 'w') as outfile:
                # Create header
                nodes = "declare -A NODES=("
                # Iterate over nodes
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
        # Add python path to PATH environment variable
        # This solves the issue of python commands executed
        # outside the virtual environment
        self.exec_cmd('export PATH=%s:$PATH' % os.path.dirname(PYTHON_PATH))
        self.exec_cmd('export SCREENDIR=/run/screen/S-%s' % self.name)
        # Run scripts
        scripts = ''
        for script in kwargs.get('scripts', []):
            # Change directory to the host dir
            self.exec_cmd('cd %s' % self.dir)
            # Get full path
            script_path = os.path.abspath(os.path.join('scripts', script))
            # Append the script to the scripts
            scripts += script_path + ' & '
        if scripts != '':
            # This line forces screen to keep opened
            # after the scripts termination
            scripts = scripts[:-3] + '; exec bash'
            # Execute the scripts
            self.exec_cmd("screen -dmS %s bash -c '%s'" % (self.name, scripts))

    # Terminate node
    def terminate(self):
        # Stop screen session
        #self.exec_cmd('screen -XS %s quit' % self.name)
        self.exec_cmd("for session in $(screen -ls | grep -o '[0-9]*\.%s'); do screen -S ${session} -X quit; done" % self.name)
        Host.terminate(self)

    # Clean up the environment
    def cleanup(self):
        Host.cleanup(self)
        # Rm dir
        if os.path.exists(self.dir):
            shutil.rmtree(self.dir)


# Abstraction to model a SRv6Controller
class SRv6Controller(MHost):

    # Config hook
    def config(self, **kwargs):

        MHost.config(self, **kwargs)


# Abstraction to model a SRv6Firewall
class WANRouter(MHost):

    # Config hook
    def config(self, **kwargs):

        MHost.config(self, **kwargs)
        # Enable IPv6 forwarding
        self.exec_cmd("sysctl -w net.ipv6.conf.all.forwarding=1")
        # Enable IPv4 forwarding
        self.exec_cmd("sysctl -w net.ipv4.conf.all.forwarding=1")
