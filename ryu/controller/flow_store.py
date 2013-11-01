# Copyright (C) 2013 University of Toronto.
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

from ryu.exception import MacAddressDuplicated, MacAddressNotFound
from ryu.lib.mac import haddr_to_str
from ryu.ofproto import ofproto_v1_0

LOG = logging.getLogger('ryu.controller.flow_store')

OFP_DEF_PRIORITY = 0x8000

FLOW_ACTIVE = 0
FLOW_PENDING = 1

FLOW_PENDING_TIME = 60

class FlowStore(object):

    def __init__(self):
        super(FlowStore, self).__init__()

        self._dps = {}
        self.pendings = {}
        self.pendings_buffer_id = {}
        self.buffers_list = []

    def _actions_equal(self, acts1, acts2):
        try:
            if len(acts1) != len(acts2):
                return False
            for index, act in enumerate(acts1):
                if act.get('type', 0) != acts2[index].get('type', 1):
                    return False
                if act.get('port', -1) != acts2[index].get('port', -2):
                    return False
            return True
        except:
            return False

    def del_port(self, dpid, port_no):
        dp_dict = self._dps.setdefault(dpid, {})
        in_port_dict = dp_dict.setdefault(port_no, None)
        if in_port_dict is not None:
            del dp_dict[port_no]

    def del_mac(self, dpid, mac):
        dp_dict = self._dps.setdefault(dpid, {})
        for port_no, in_port_dict in dp_dict.iteritems():
            if in_port_dict is not None:
                dest_mac_dict = in_port_dict.get(mac, {})
                for src_mac_list in dest_mac_dict.values():
                    del src_mac_list
                del in_port_dict[mac]
                # now need to delete src_macs in other dest dics
                for d_mac, dest_mac_dict in in_port_dict.iteritems():
                    for src_mac_list in dest_mac_dict.values():
                        if mac in src_mac_list:
                            src_mac_list.remove(mac)
        return


    def get_all_flows(self, dpid = None):
        if dpid is None:
            return self._dps
        return self._dps.get(dpid, {})

    def get_flow(self, dpid, in_port, src, dst, eth_type, pending = False):
        dp_dict = self._dps.get(dpid, {})
        in_port_dict = dp_dict.get(in_port, {})
        dest_mac_dict = in_port_dict.get(dst, {})
        if src is None:
            temp_src = '0'
            with_source = 0
        else:
            temp_src = src
            with_source = 1

        look_for_pending = False
        src_mac_list = dest_mac_dict.get(temp_src, [])
        for index, (pr, eth_t, acts, out_ports, idle_timeout, hard_timeout, nums) in enumerate(src_mac_list):
            if eth_t is None or eth_type == eth_t:
                LOG.info("found : %s,%s,%s,%s,%s,%s" % (pr, eth_t, acts, out_ports, idle_timeout, hard_timeout))
                return (pr, eth_t, acts, out_ports, idle_timeout, hard_timeout, with_source)

        with_source = 0
        src_mac_list = dest_mac_dict.get('0', [])
        for index, (pr, eth_t, acts, out_ports, idle_timeout, hard_timeout, nums) in enumerate(src_mac_list):
            if eth_t is None or eth_type == eth_t:
                ret = (pr, eth_t, acts, out_ports, idle_timeout, hard_timeout, with_source)
                LOG.info("found : %s" % (ret,))
                return ret

        return (None, None, None, None, None, None, None)

    def add_flow_dict(self, flow):
        match = flow.get('match', {})
        # first check to see if it is a dhcp flow
        if match.get('tp_src', 0) == 68:
            # this is a dhcp flow, no need to add to store
            return
        priority = flow.get('priority', OFP_DEF_PRIORITY)
        src = match.get('dl_src', None)
        dest = match.get('dl_dst', None)
        eth_type = match.get('dl_type', None)
        in_port = match.get('in_port', None)
        dpid = flow.get('dpid', None)
        actions = flow.get('actions', {})

        out_port = flow.get('out_port', ofproto_v1_0.OFPP_NONE)
        idle_timeout = flow.get('idle_timeout', 0)
        hard_timeout = flow.get('hard_timeout', 0)

        if dpid is not None and dest is not None:
            self.add_flow(dpid, in_port, dest, src, eth_type, actions, priority, out_port, idle_timeout, hard_timeout)
        return

    def del_flow_dict(self, flow):
        priority = flow.get('priority', OFP_DEF_PRIORITY)
        match = flow.get('match', {})
        src = match.get('dl_src', None)
        dest = match.get('dl_dst', None)
        eth_type = match.get('dl_type', None)
        in_port = match.get('in_port', None)
        dpid = flow.get('dpid', None)
        actions = flow.get('actions', {})

        if dpid is not None:
            self.del_flow(dpid, in_port, dest, src, eth_type)
        return

    def add_flow(self, dpid, in_port, dest, src, eth_type, actions, priority, out_port, idle_timeout, hard_timeout):
        ret = True

        dp_dict = self._dps.setdefault(dpid, {})
        in_port_dict = dp_dict.setdefault(in_port, {})
        dest_mac_dict = in_port_dict.setdefault(dest, {})
        if src is None:
            temp_src = '0'
        else:
            temp_src = src
        src_mac_list = dest_mac_dict.setdefault(temp_src, [])

        if len(src_mac_list) > 0:
            for index, (pr, eth_t, acts, o, i1, j1, nums) in enumerate(src_mac_list):
                if eth_type is not None and eth_type != eth_t:
                    continue
                if priority == pr and self._actions_equal(acts, actions):
                    ret = False
                    src_mac_list[index] = (pr, eth_t, acts, out_port, idle_timeout, hard_timeout, nums + 1)
#                    LOG.info("updated : %s,%s,%s,%s,%s,%s,%s" % (priority, eth_t, actions, out_port, idle_timeout, hard_timeout, nums + 1))
                    break;

        if ret:
            src_mac_list.append((priority, eth_type, actions, out_port, idle_timeout, hard_timeout, 1))
 #          LOG.info("added : %s,%s,%s,%s,%s,%s,%s" % (priority, eth_type, actions, out_port, idle_timeout, hard_timeout, 1))

        return ret

    def del_flow(self, dpid, in_port, dest, src, eth_type):
        ret = False
        found = False

        dp_dict = self._dps.setdefault(dpid, {})
        for in_p, in_p_dict in dp_dict.iteritems():
            if in_port is not None and in_port != in_p:
                continue
            for dst, dest_mac_dict in in_p_dict.iteritems():
                if dest is not None and dest != dst:
                    continue
                for sr, src_mac_list in dest_mac_dict.iteritems():
                    if src is not None and src != sr:
                        continue
                    for index, (pr, eth_t, acts, out_ports, idle_timeout, hard_timeout, nums) in enumerate(src_mac_list):
                        if eth_type is not None and eth_t != eth_type:
                            continue
                        src_mac_list[index] = (pr, eth_t, acts, out_ports, idle_timeout, hard_timeout, nums - 1)
                        found = True
                        if (nums - 1) == 0:
                            ret = True;
                            del src_mac_list[index]
                        break;

        if not found :
            ret = True

        return ret

    def add_msg_to_pending(self, buffer_id, dpid, in_port, src, dst, eth_type):
        self.pendings.setdefault(dpid, {})
        self.pendings[dpid].setdefault(in_port, {})
        self.pendings[dpid][in_port].setdefault(dst, {})
        self.pendings[dpid][in_port][dst].setdefault(src, {})

        (buffers, t) = self.pendings[dpid][in_port][dst][src].setdefault(eth_type, ([], time.time()))
        if len(buffers) < 5:
            buffers.append(buffer_id)
        else:
            return False

#        LOG.info("add msg to pending  %s, %s, %s, %s", dpid, in_port, buffer_id, buffers)
        self.pendings_buffer_id.setdefault(dpid, {})
        self.pendings_buffer_id[dpid].setdefault(in_port, {})
        self.pendings_buffer_id[dpid][in_port][buffer_id] = (src, dst, eth_type)
        self.buffers_list.append((dpid, in_port, buffer_id))
        return True

    def check_if_similar_msg_pending(self, buffer_id, dpid, in_port, src, dst, eth_type):
        try:
            (buffers, time_stamp) = self.pendings[dpid][in_port][dst][src][eth_type]
#           LOG.info("check similar pending msgs %s, %s, %s, %s", dpid, in_port, buffer_id, buffers)
        except:
            buffers = None
            pass
        if buffers is not None:
            if time.time() - time_stamp > 60:
                del self.pendings[dpid][in_port][dst][src][eth_type]
                for id in buffers:
                    try:
                        del self.pendings_buffer_id[dpid][in_port][id]
                    except:
                        pass
                    try:
                        self.buffers_list.remove((dpid, in_port, id))
                    except:
                        pass
                del buffers
                return False
            """
            if len(buffers) < 5:
                buffers.append(buffer_id)
                self.pendings_buffer_id.setdefault(dpid, {})
                self.pendings_buffer_id[dpid].setdefault(in_port, {})
                self.pendings_buffer_id[dpid][in_port][buffer_id] = (src, dst, eth_type)
                self.buffers_list.append((dpid, in_port, buffer_id))
            """
            return True
        else:
            return False

    def remove_msg_from_pending(self, dpid, in_port, buffer_id):
        try:
            (src, dst, eth_type) = self.pendings_buffer_id[dpid][in_port][buffer_id]
            (buffers, time_stamp) = self.pendings[dpid][in_port][dst][src][eth_type]
#           LOG.info("remove pending msgs %s, %s, %s, %s", dpid, in_port, buffer_id, buffers)
            for id in buffers:
                try:
                    del self.pendings_buffer_id[dpid][in_port][id]
                except:
                    pass
                try:
                    self.buffers_list.remove((dpid, in_port, id))
                except:
                    pass
            del buffers
            try:
                del self.pendings_buffer_id[dpid][in_port][buffer_id]
            except:
                pass
            try:
                del self.pendings[dpid][in_port][dst][src][eth_type]
            except:
                pass
            try:
                self.buffers_list.remove((dpid, in_port, buffer_id))
            except:
                pass
        except:
            pass

    def get_similar_pending_msgs(self, dpid, in_port, buffer_id):
        try:
            (src, dst, eth_type) = self.pendings_buffer_id[dpid][in_port][buffer_id]
            (buffers, time_stamp) = self.pendings[dpid][in_port][dst][src][eth_type]
#           LOG.info("get similar pending msgs %s, %s, %s, %s", dpid, in_port, buffer_id, buffers)
            return buffers
        except:
            pass
        return []

    def clear_expired_pending_msgs(self):
        expired_list = []
        for index, (dpid, in_port, buffer_id) in enumerate(self.buffers_list):
            try:
                (src, dst, eth_type) = self.pendings_buffer_id[dpid][in_port][buffer_id]
                (buffers, time_stamp) = self.pendings[dpid][in_port][dst][src][eth_type]
                if buffers is not None and time.time() - time_stamp > 60:
#                   LOG.info("deleting  expired pending msg %s", buffers)
                    expired_list.append((dpid, in_port, buffer_id))
                    for id in buffers:
                        try:
                            del self.pendings_buffer_id[dpid][in_port][id]
                        except:
                            pass
                        try:
                            self.buffers_list.remove((dpid, in_port, id))
                        except:
                            pass
                    del buffers
                    try:
                        del self.pendings_buffer_id[dpid][in_port][buffer_id]
                    except:
                        pass
                    try:
                        del self.pendings[dpid][in_port][dst][src][eth_type]
                    except:
                        pass
                    try:
                        buffer_list.remove((dpid, in_port, buffer_id))
                    except:
                        pass
            except:
                pass
        return expired_list
