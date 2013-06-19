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

from ryu.exception import MacAddressDuplicated, MacAddressNotFound
from ryu.lib.mac import haddr_to_str
from ryu.app.rest_nw_id import NW_ID_MGMT_CTRL, NW_ID_PXE_CTRL

LOG = logging.getLogger('ryu.controller.mac_to_network')


class MacToNetwork(object):
    def __init__(self):
        super(MacToNetwork, self).__init__()
        self.mac_to_net = {}
        self.dpid = {}

    def get_network(self, mac, default=None):
        return self.mac_to_net.get(mac, default)

    def add_mac(self, mac, nw_id, nw_id_external=None):
        _nw_id = self.mac_to_net.get(mac)
        if _nw_id == nw_id:
            return

        # allow changing from nw_id_external to known nw id
        if _nw_id is None or _nw_id == nw_id_external:
            self.mac_to_net[mac] = nw_id
            LOG.debug('overwrite nw_id: mac %s nw old %s new %s',
                      haddr_to_str(mac), _nw_id, nw_id)
            return

        if nw_id == nw_id_external or nw_id == NW_ID_MGMT_CTRL or nw_id == NW_ID_PXE_CTRL:
            # this can happens when the packet traverses
            # VM-> tap-> ovs-> ext-port-> wire-> ext-port-> ovs-> tap-> VM
            return

        LOG.warn('duplicated nw_id: mac %s nw old %s new %s',
                 haddr_to_str(mac), _nw_id, nw_id)

        raise MacAddressDuplicated(mac=mac)

    def del_mac(self, mac):
        try:
            del self.mac_to_net[mac]
        except:
            raise MacAddressNotFound(mac=mac)
    
    def list_macs(self, nw_id):
        mac_list = []
        for k, v in self.mac_to_net.items():
            if (v == nw_id):
               mac_list.append(k)
        
        return mac_list
