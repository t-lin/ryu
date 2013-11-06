# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import time
from copy import deepcopy
from ryu.lib.mac import haddr_to_str, ipaddr_to_str
from janus.network.of_controller.janus_of_consts import ARP_TIMEOUT

LOG = logging.getLogger('ryu.controller.mac_to_port')


class MacToPortTable(object):
    """MAC addr <-> (dpid, port name)"""

    def __init__(self):
        super(MacToPortTable, self).__init__()
#        self._mac_to_port = {}
        self._ip_to_mac = {}
        self._mac_to_ip = {}

    """
    def dpid_add(self, dpid):
        LOG.debug('dpid_add: 0x%016x', dpid)
        self._mac_to_port.setdefault(dpid, {})
        # self._ip_to_mac.setdefault(dpid, {})

    def port_add(self, dpid, port, mac, ip = None):
        self._mac_to_port.setdefault(dpid, {})
        old_port = self._mac_to_port[dpid].get(mac, None)
        self._mac_to_port[dpid][mac] = port
        # self._ip_to_mac[dpid][ip] = mac
        if ip is not None:
            self._ip_to_mac[ip] = mac
            self._mac_to_ip[mac] = ip

        if old_port is not None and old_port != port:
            LOG.debug('port_add: 0x%016x 0x%04x %s',
                      dpid, port, haddr_to_str(mac))

        return old_port

    def port_get(self, dpid, mac):
        # LOG.debug('dpid 0x%016x mac %s', dpid, haddr_to_str(mac))
        return self._mac_to_port[dpid].get(mac)

    def mac_list(self, dpid, port):
        return [mac for (mac, port_) in self._mac_to_port.get(dpid, {}).items()
                if port_ == port]

    def mac_del(self, dpid, mac):
        del self._mac_to_port[dpid][mac]
        self.mac_ip_del(mac)
    """

    def mac_ip_del(self, mac, ip = None):
        if ip is not None:
            self._ip_to_mac.pop(ip, (None, None))

        ip1 = self._mac_to_ip.get(mac, None)
        self._mac_to_ip.pop(mac, None)
        if ip1 is not None:
            self._ip_to_mac.pop(ip1, (None, None))
            LOG.info('mac ip deleted %s, %s', haddr_to_str(mac), ipaddr_to_str(ip1))
        else:
            LOG.info('mac ip deleted %s', haddr_to_str(mac))

    def mac_ip_add(self, mac, ip):
        if ip is not None:
            self._ip_to_mac[ip] = (mac, time.time())
        if mac is not None:
            self._mac_to_ip[mac] = ip
        LOG.info('mac ip added %s, %s', haddr_to_str(mac), ipaddr_to_str(ip))

    def mac_ip_get(self, ip):
        mac = None
        if ip is not None:
            (mac, time_stamp) = self._ip_to_mac.get(ip, (None, None))
            if mac is not None and time_stamp is not None:
                if (time.time() - time_stamp) > ARP_TIMEOUT:
                    self.mac_ip_del(mac, ip)
                    mac = None
        return mac

    def get_ip_to_mac_dict(self):
        return self._ip_to_mac

    def clear_old_entries_in_ip_mac(self):
        now = time.time()
        dict_copy = deepcopy(self._ip_to_mac)
        for ip, (mac, time_stamp) in dict_copy.iteritems():
             if (now - time_stamp) > ARP_TIMEOUT:
                 self.mac_ip_del(mac, ip)

