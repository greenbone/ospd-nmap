# -*- coding: utf-8 -*-
# Description:
# Setup for the OSP nmap Server
#
# Authors:
# Jan-Oliver Wagner <Jan-Oliver.Wagner@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

import subprocess

from ospd.ospd import OSPDaemon, OSPDError
from ospd.misc import main as daemon_main
from ospd_nmap import __version__
import defusedxml.ElementTree as secET

OSPD_DESC = """
This scanner runs the tool 'nmap' to scan the target hosts.

This tool is available for most operating systems and identifies open ports,
probes the services, operating systems and even can run more sophisticated
detection routines.

For more details about nmap see the nmap homepage:
http://nmap.org/

The current version of ospd-nmap is a very simple one, only retrieving
open tcp/udp ports and service. It is possible to choice scan techniques,
to set OS detection, and to set timing and performance options.
"""

OSDET_DIC = {
    'Disable': 'Disable',
    'Enable': '-O',
    'Guess': '--osscan-guess',
    'Limit': '--osscan-limit',
}

TIMING_DIC = {
    'Disable': 'Disable',
    'Paranoid': '-T0',
    'Sneaky': '-T1',
    'Polite': '-T2',
    'Normal': '-T3',
    'Aggressive': '-T4',
    'Insane': '-T5',
}

SCANTYPE_DIC = {
    'Disable': 'Disable',
    'Connect()': '-sT',
    'SYN': '-sS',
    'ACK': '-sA',
    'FIN': '-sF',
    'Window': '-sW',
    'Maimon': '-sM',
    'Xmas tree': '-sX',
    'Null': '-sN',
    'Idle scan': '-sI',
}

SCTP_SCANTYPE_DIC = {
    'Disable': 'Disable',
    'SCTP Init': '-sY',
    'SCTP COOKIE_ECHO': '-sZ',
}

BOOL_OPT_DIC = {
    'allhoston': '-Pn',
    'traceroute': '--traceroute',
    'nodns': '-n',
    'servscan': '-sV',
    'fragmentip': '-f',
}

INT_OPT_DIC = {
    'sourceport': '-g',
    'minportpar': '--min-parallelism',
    'maxportpar': '--max-parallelism',
    'minhostpar': '--min-hostgroup',
    'maxhostpar': '--max-hostgroup',
}

TIME_OPT_DIC = {
    'htimeout': '--host-timeout',
    'minrtttimeout': '--min-rtt-timeout',
    'maxrtttimeout': '--max-rtt-timeout',
    'initrtttimeout': '--initial-rtt-timeout',
    'interprobedelay': '--scan-delay',
}

OSDET_ARGS = [
    'Disable',
    'Enable',
    'Guess',
    'Limit',
    'Disable',
]

TIMING_ARGS = [
    'Disable',
    'Paranoid',
    'Sneaky',
    'Polite',
    'Normal',
    'Aggressive',
    'Insane',
    'Disable',
]

SCANTYPE_ARGS = [
    'Connect()',
    'SYN',
    'Connect()',
    'ACK',
    'FIN',
    'Window',
    'Maimon',
    'Xmas tree',
    'Null',
    'Idle scan',
    'Disable',
]

SCTP_SCANTYPE_ARGS = [
    'Disable',
    'SCTP Init',
    'SCTP COOKIE_ECHO',
    'Disable',
]

OSPD_PARAMS = {
    'dumpxml': {
        'type': 'boolean',
        'name': 'Dump the XML output of nmap',
        'default': 0,
        'mandatory': 0,
        'description': 'Whether to create a log result with the raw XML output of nmap.',
    },
    'allhoston': {
        'type': 'boolean',
        'name': 'All hosts as online',
        'default': 0,
        'mandatory': 0,
        'description': 'Treat all hosts as online.',
    },
    'traceroute': {
        'type': 'boolean',
        'name': 'Traceroute',
        'default': 0,
        'mandatory': 0,
        'description': 'Trace hop path to each host.',
    },
    'nodns': {
        'type': 'boolean',
        'name': 'DNS resolution',
        'default': 0,
        'mandatory': 0,
        'description': 'Disable DNS resolution.',
    },
    'servscan': {
        'type': 'boolean',
        'name': 'Service scan',
        'default': 1,
        'mandatory': 0,
        'description': 'Perform service/version detection scan.',
    },
    'fragmentip': {
        'type': 'boolean',
        'name': 'Fragment IP packets (bypasses firewalls)',
        'default': 0,
        'mandatory': 0,
        'description': 'Try ti evade defense by fragmenting IP packets.',
    },
    'sourceport': {
        'type': 'integer',
        'name': 'Source port',
        'default': 0,
        'mandatory': 0,
        'description': 'Set source port.',
    },
    'htimeout': {
        'type': 'integer',
        'name': 'Host Timeout (ms)',
        'default': 0,
        'mandatory': 0,
        'description': 'Give up on host after this time elapsed.',
    },
    'minrtttimeout': {
        'type': 'integer',
        'name': 'Min RTT Timeout (ms)',
        'default': 0,
        'mandatory': 0,
        'description': 'Probe round trip time hint (minimal value).',
    },
    'maxrtttimeout': {
        'type': 'integer',
        'name': 'Max RTT Timeout (ms)',
        'default': 0,
        'mandatory': 0,
        'description': 'Probe round trip time hint (maximal value).',
    },
    'initrtttimeout': {
        'type': 'integer',
        'name': 'Initial RTT Timeout (ms)',
        'default': 0,
        'mandatory': 0,
        'description': 'Probe round trip time hint (initial value).',
    },
    'minportpar': {
        'type': 'integer',
        'name': 'Ports scanned in parallel (min)',
        'default': 0,
        'mandatory': 0,
        'description': 'Force minimum number of parallel active probes.',
    },
    'maxportpar': {
        'type': 'integer',
        'name': 'Ports scanned in parallel (max)',
        'default': 0,
        'mandatory': 0,
        'description': 'Force maximum number of parallel active probes.',
    },
    'minhostpar': {
        'type': 'integer',
        'name': 'Hosts scanned in parallel (min)',
        'default': 0,
        'mandatory': 0,
        'description': 'Force minimum number of host to scan in parallel.',
    },
    'maxhostpar': {
        'type': 'integer',
        'name': 'Hosts scanned in parallel (max)',
        'default': 0,
        'mandatory': 0,
        'description': 'Force maximum number of host to scan in parallel.',
    },
    'interprobedelay': {
        'type': 'integer',
        'name': 'Minimum wait between probes (ms)',
        'default': 0,
        'mandatory': 0,
        'description': 'Set idle interval between probes.',
    },
    'timing': {
        'type': 'selection',
        'name': 'Timing policy',
        'default': '|'.join(TIMING_ARGS),
        'mandatory': 0,
        'description': 'Add timing argument to the Nmap command.',
    },
    'osdet': {
        'type': 'selection',
        'name': 'OS Detection',
        'default': '|'.join(OSDET_ARGS),
        'mandatory': 0,
        'description': 'Enable OS detection. Limit option limits OS detection to promising targets. Guess option guess OS more aggresively',
    },
    'scantype': {
        'type': 'selection',
        'name': 'Scan type',
        'default': '|'.join(SCANTYPE_ARGS),
        'mandatory': 0,
        'description': 'Add the TCP scan type flag to the command line.',
    },
    'sctpscantype': {
        'type': 'selection',
        'name': 'SCTP Scan type',
        'default': '|'.join(SCTP_SCANTYPE_ARGS),
        'mandatory': 0,
        'description': 'Add the SCTP scan type flag to the command line.',
    },
}


class OSPDnmap(OSPDaemon):

    """ Class for ospd-nmap daemon. """

    def __init__(self, certfile, keyfile, cafile):
        """ Initializes the ospd-nmap daemon's internal data. """
        super(OSPDnmap, self).__init__(certfile=certfile, keyfile=keyfile,
                                       cafile=cafile)
        self.server_version = __version__
        self.scanner_info['name'] = 'nmap'
        self.scanner_info['version'] = ''  # achieved during self.check()
        self.scanner_info['description'] = OSPD_DESC
        for name, param in OSPD_PARAMS.items():
            self.add_scanner_param(name, param)

    def process_scan_params(self, params):
        """ params is directly from the XML """
        for param in OSPD_PARAMS:
            if param in ('dumpxml', 'allhoston', 'traceroute', 'nodns', 'servscan',
                         'fragmentip', 'sourceport', 'htimeout', 'minrtttimeout',
                         'maxrtttimeout', 'initrtttimeout', 'minportpar',
                         'maxportpar', 'minhostpar', 'maxhostpar',
                         'interprobedelay',):
                continue
            if not params.get(param):
                raise OSPDError('Empty %s value' % param, 'start_scan')
        return params

    def check(self):
        """ Checks that nmap command line tool is found and is executable. """

        try:
            result = subprocess.check_output(['nmap', '-oX', '-'],
                                             stderr=subprocess.STDOUT)
        except OSError:
            # the command is not available
            return False

        if result is None:
            return False

        tree = secET.fromstring(result)

        if tree.tag != 'nmaprun':
            return False

        version = tree.attrib.get('version')
        if version == '':
            return False

        self.scanner_info['version'] = version

        return True

    def exec_scan(self, scan_id, target):
        """ Starts the nmap scanner for scan_id scan. """

        ports = self.get_scan_ports(scan_id)
        options = self.get_scan_options(scan_id)
        dump = options.get('dumpxml')
        timingpolicy = options.get('timing')
        os_detection = options.get('osdet')
        scan_t = options.get('scantype')
        sctp_scan_t = options.get('sctpscantype')
        source_port = options.get('sourceport')
        traceroute = options.get('traceroute')

        # Add default options to nmap command string, that is scan
        # for udp/tcp port and output in xml format.
        command_str = ['nmap']
        for elem in ['-oX', '-']:
            command_str.append(elem)
        if 'U' in ports:
            command_str.append('-sU')

        # Add all enabled options
        # All boole options
        for opt in ('allhoston', 'traceroute', 'nodns', 'servscan', 'fragmentip',):
            if options.get(opt):
                command_str.append(BOOL_OPT_DIC[opt])

        # Add all selection options
        if timingpolicy != 'Disable':
            command_str.append(TIMING_DIC[timingpolicy])

        if scan_t != 'Disable':
            command_str.append(SCANTYPE_DIC[scan_t])

        if sctp_scan_t != 'Disable':
            command_str.append(SCTP_SCANTYPE_DIC[sctp_scan_t])

        if os_detection != 'Disable':
            command_str.append('-O')
            if os_detection != 'Enable':
                command_str.append(OSDET_DIC[os_detection])

        # Add all integer options
        for opt in ('minportpar', 'maxportpar', 'minhostpar', 'sourceport', 'maxhostpar',):
            if options.get(opt) != 0:
                command_str.append(str(INT_OPT_DIC[opt]))
                command_str.append(str(options.get(opt)))

                # Add all integer options
        for opt in ('htimeout', 'minrtttimeout', 'maxrtttimeout', 'initrtttimeout',
                    'interprobedelay',):
            if options.get(opt) != 0:
                # for elem in []
                command_str.append(str(TIME_OPT_DIC[opt]))
                command_str.append(str(options.get(opt))+'ms')

        # Add port list and target to nmap command string.
        for elem in ['-p %s' % ports, target]:
            command_str.append(elem)

        # Run Nmap
        result = None
        try:
            result = subprocess.check_output(command_str,
                                             stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            self.add_scan_error(
                scan_id, host=target,
                value="A problem occurred trying to execute 'nmap'."
            )
            self.add_scan_error(
                scan_id, host=target,
                value="The result of 'nmap' was empty."
            )
            return 2

        if result is None:
            self.add_scan_error(
                scan_id, host=target,
                value="A problem occurred trying to execute 'nmap'."
            )
            self.add_scan_error(
                scan_id, host=target,
                value="The result of 'nmap' was empty."
            )
            return 2

        # If "dump" was set to True, then create a log entry with the dump.
        if dump == 1:
            self.add_scan_log(scan_id, host=target, name='Nmap dump',
                              value='Raw nmap output:\n\n%s' % result)

        # initialize the port list
        tcp_ports = []
        udp_ports = []
        ports = []

        # parse the output of the nmap command
        tree = secET.fromstring(result)
        if tree.find("host/ports") is not None:
            for port in tree.find("host/ports"):
                aux_list = []
                if port.tag == 'port':
                    aux_list.append(port.attrib.get('protocol'))
                    aux_list.append(port.attrib.get('portid'))
                    state = port.find('state')
                    aux_list.append(state.get('state'))
                    if options.get('servscan') == 1:
                        service = port.find('service')
                        aux_list.append(service.get('name'))
                        aux_list.append(service.get('product'))
                        aux_list.append(service.get('version'))
                        aux_list.append(service.get('extrainfo'))
                    ports.append(aux_list)
                    if aux_list[0] == 'tcp' and aux_list[2] != 'closed':
                        tcp_ports.append(aux_list[1])
                    elif aux_list[0] == 'udp' and aux_list[2] != 'closed':
                        udp_ports.append(aux_list[1])

        # Create a general log entry about executing nmap
        # It is important to send at least one result, else
        # the host details won't be stored.
        self.add_scan_log(scan_id, host=target, name='Nmap summary',
                          value='Via Nmap %d tcp ports and %d udp were found.'
                          % (len(tcp_ports), len(udp_ports)))

        # Create a log entry for OS detected
        if os_detection != 'Disable' and (tree.find("host/os") is not None):
            osname = ''
            for opsys in tree.find("host/os"):
                if opsys.tag == 'osmatch':
                    osname = opsys.attrib.get('name')
                    osaccuracy = opsys.attrib.get('accuracy')
            if osname != '':
                self.add_scan_log(scan_id, host=target, name='OS detected',
                                  value='Via Nmap %s OS Detected, accuracy = %s' % (osname, osaccuracy))

        # Create a log entry for traceroute
        if traceroute and (tree.find("host/trace") is not None):
            tracert = ''
            for opsys in tree.find("host/trace"):
                if opsys.tag == 'hop':
                    hopttl = opsys.attrib.get('ttl')
                    hopaddr = opsys.attrib.get('ipaddr')
                tracert = '%s%s' % (tracert,
                                    'ttl= {0} ipaddr={1} \n'.format(hopttl, hopaddr))
            if tracert != '':
                self.add_scan_log(scan_id, host=target, name='Traceroute',
                                  value=tracert)

        if tree.find("runstats") is not None:
            for stat in tree.find("runstats"):
                down = "0"
                if stat.tag == 'hosts':
                    down = stat.attrib.get('down')
                if down > "0":
                    self.add_scan_log(scan_id, host=target, name='Host down',
                                      value=down)

        # Create a log entry for each found service or found port
        for found_port in ports:

            if len(found_port) <= 3 and found_port[2] != 'closed':
                self.add_scan_log(scan_id, host=target,
                                  name='Nmap port detection',
                                  port='{0}/{1}'.format(found_port[1],
                                                        found_port[0]))
            elif len(found_port) > 3 and found_port[3] != 'none' and found_port[2] != 'closed':
                self.add_scan_log(scan_id, host=target,
                                  name='Nmap service detection',
                                  port='{0} running on port {1}/{2}. State: {3}'.format(found_port[3],
                                                                                        found_port[1],
                                                                                        found_port[0],
                                                                                        found_port[2]))

        # store the found ports as host details
        if len(tcp_ports) > 0:
            self.add_scan_host_detail(scan_id, host=target, name="ports",
                                      value=", ".join(tcp_ports))
            self.add_scan_host_detail(scan_id, host=target, name="tcp_ports",
                                      value=", ".join(tcp_ports))
        if len(udp_ports) > 0:
            self.add_scan_host_detail(scan_id, host=target, name="ports",
                                      value=", ".join(udp_ports))
            self.add_scan_host_detail(scan_id, host=target, name="udp_ports",
                                      value=", ".join(udp_ports))
        return 1


def main():
    """ OSP nmap main function. """
    daemon_main('OSPD - nmap wrapper', OSPDnmap)
