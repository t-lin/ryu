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
from ryu.controller import api_db

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
        self.dpid_ids = {}
        self.dpid_nums = {}
        self._dhcp_flow = {}
        self._mac_flows_dict = {}

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
        dp_dict = self._dps.get(dpid, None)
        if dp_dict is not None:
            in_port_dict = dp_dict.get(port_no, None)
            if in_port_dict is not None:
                del dp_dict[port_no]

    """
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
    """

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
        for index, (id, pr, eth_t, acts, out_ports, idle_timeout, hard_timeout, nums) in enumerate(src_mac_list):
            if eth_t is None or eth_type == eth_t:
                LOG.info("found : %s,%s,%s,%s,%s,%s" % (pr, eth_t, acts, out_ports, idle_timeout, hard_timeout))
                return (id, pr, eth_t, acts, out_ports, idle_timeout, hard_timeout, with_source)

        with_source = 0
        src_mac_list = dest_mac_dict.get('0', [])
        for index, (id, pr, eth_t, acts, out_ports, idle_timeout, hard_timeout, nums) in enumerate(src_mac_list):
            if eth_t is None or eth_type == eth_t:
                ret = (id, pr, eth_t, acts, out_ports, idle_timeout, hard_timeout, with_source)
                LOG.info("found : %s" % (ret,))
                return ret

        return (None, None, None, None, None, None, None, None)

    def add_dhcp_flow(self, dpid, in_port, src, actions):
        self._dhcp_flow.setdefault(dpid, {})
        self._dhcp_flow[dpid].setdefault(in_port, {})
        self._dhcp_flow[dpid][in_port][src] = actions
        return

    def del_dhcp_flow(self, dpid, in_port, src):
        try:
            del self._dhcp_flow[dpid][in_port][src]
        except:
            pass

    def get_dhcp_flow(self, dpid, in_port, src):
        try:
            return self._dhcp_flow[dpid][in_port][src]
        except:
            return None

    def add_flow_dict(self, flow, api_db):
        match = flow.get('match', {})
        # first check to see if it is a dhcp flow
        priority = flow.get('priority', OFP_DEF_PRIORITY)
        src = match.get('dl_src', None)
        dest = match.get('dl_dst', None)
        eth_type = match.get('dl_type', None)
        in_port = match.get('in_port', None)
        dpid = flow.get('dpid', None)
        actions = flow.get('actions', {})
        if match.get('tp_src', 0) == 68 and eth_type == 0x800:
            # this is a dhcp flow, no need to add to store
            self.add_dhcp_flow(dpid, in_port, src, actions)
            return

        out_port = flow.get('out_port', ofproto_v1_0.OFPP_NONE)
        idle_timeout = flow.get('idle_timeout', 0)
        hard_timeout = flow.get('hard_timeout', 0)

        if dpid is not None and dest is not None:
            self.add_flow(api_db, dpid, in_port, dest, src, eth_type, actions, priority, out_port, idle_timeout, hard_timeout)
        return

    def del_flow_dict(self, flow, api_db):
        priority = flow.get('priority', OFP_DEF_PRIORITY)
        match = flow.get('match', {})
        src = match.get('dl_src', None)
        dest = match.get('dl_dst', None)
        eth_type = match.get('dl_type', None)
        in_port = match.get('in_port', None)
        dpid = flow.get('dpid', None)
        actions = flow.get('actions', {})

        if dpid is not None:
            self.del_flow(api_db, dpid, in_port, dest, src, eth_type)
        return

    def largest_id(self, dpid):
        return self.dpid_ids.get(dpid, 0)

    def number_of_flows(self, dpid):
        return self.dpid_nums.get(dpid, 0)

    def add_flow(self, api_db, dpid, in_port, dest, src, eth_type, actions, priority, out_port, idle_timeout, hard_timeout, id = -1):
        ret = True

        dp_dict = self._dps.setdefault(dpid, {})
        in_port_dict = dp_dict.setdefault(in_port, {})
        if in_port_dict is None:
            dp_dict[in_port] = {}
            in_port_dict = dp_dict[in_port]
        dest_mac_dict = in_port_dict.setdefault(dest, {})
        if dest_mac_dict is None:
            in_port_dict[dest] = {}
            dest_mac_dict = in_port_dict[dest]
        if src is None:
            temp_src = '0'
        else:
            temp_src = src
        src_mac_list = dest_mac_dict.setdefault(temp_src, [])
        if src_mac_list is None:
            dest_mac_dict[temp_src] = []
            src_mac_list = dest_mac_dict[temp_src]

        if len(src_mac_list) > 0:
            for index, (id1, pr, eth_t, acts, o, i1, j1, nums) in enumerate(src_mac_list):
                if eth_type is not None and eth_type != eth_t:
                    continue
                if priority == pr and self._actions_equal(acts, actions):
                    ret = False
                    src_mac_list[index] = (id1, pr, eth_t, acts, out_port, idle_timeout, hard_timeout, nums + 1)
#                    LOG.info("updated : %s,%s,%s,%s,%s,%s,%s" % (priority, eth_t, actions, out_port, idle_timeout, hard_timeout, nums + 1))
                    break

        if ret:
            if api_db is not None:
                try:
                    id = api_db.add_flow(str(hex(dpid)), in_port, dest, src, priority, eth_type, actions, out_port, idle_timeout, hard_timeout)
                except:
                    id = -1
                    raise
            if id > self.dpid_ids.get(dpid, 0):
                self.dpid_ids[dpid] = id
            self.dpid_nums[dpid] = self.dpid_nums.get(dpid, 0) + 1
            src_mac_list.append((id, priority, eth_type, actions, out_port, idle_timeout, hard_timeout, 1))
            if src is not None:
                self.add_mac_flow(dpid, in_port, src, True, dest)
            self.add_mac_flow(dpid, in_port, dest, False, src)
 #          LOG.info("added : %s,%s,%s,%s,%s,%s,%s" % (priority, eth_type, actions, out_port, idle_timeout, hard_timeout, 1))

        return ret

    def del_flow(self, api_db, dpid, in_port, dest, src, eth_type):
        ret = False
        found = False

        dp_dict = self._dps.get(dpid, None)
        if dp_dict is None:
            return True
        in_p_to_be_removed = []
        for in_p, in_p_dict in dp_dict.iteritems():
            if in_port is not None and in_port != in_p:
                continue
            dst_to_be_removed = []
            for dst, dest_mac_dict in in_p_dict.iteritems():
                if dest is not None and dest != dst:
                    continue
                elements_be_removed = []
                for sr, src_mac_list in dest_mac_dict.iteritems():
                    if src is not None and src != sr:
                        continue
                    index_to_be_removed = []
                    for index, (id, pr, eth_t, acts, out_ports, idle_timeout, hard_timeout, nums) in enumerate(src_mac_list):
                        if eth_type is not None and eth_t != eth_type:
                            continue
                        src_mac_list[index] = (id, pr, eth_t, acts, out_ports, idle_timeout, hard_timeout, nums - 1)
                        found = True
#                        if (nums - 1) == 0:
                        ret = True
                        index_to_be_removed.append(index)
                        self.dpid_nums[dpid] = self.dpid_nums[dpid] - 1
                        if api_db and id != -1:
                            try:
                                api_db.del_flow(str(hex(dpid)), in_p, dst, id)
                            except:
                                raise
                    index_to_be_removed.reverse()
                    for index in index_to_be_removed:
                        del src_mac_list[index]
                    if len(src_mac_list) == 0:
                        elements_be_removed.append(sr)

                for sr in elements_be_removed:
                    del dest_mac_dict[sr]
                if len(dest_mac_dict) == 0:
                    dst_to_be_removed.append(dst)

            for dst in dst_to_be_removed:
                del in_p_dict[dst]
            if len(in_p_dict) == 0:
                in_p_to_be_removed.append(in_p)

        for in_p in in_p_to_be_removed:
            del dp_dict[in_p]

        if not found :
            ret = True

        return ret

    def add_mac_flow(self, dpid, port, mac, src_or_dst, other_mac):
        flows_list = self._mac_flows_dict.setdefault(mac, [])
        flows_list.append((dpid, port, src_or_dst, other_mac))
        return

    def del_mac_flows(self, dpid, port_no, mac):
        flows_list = self._mac_flows_dict.get(mac, None)
        if flows_list is not None:
            for (dp_id, port, src_or_dst, other_mac) in flows_list:
                if src_or_dst:
                    self.del_flow(None, dp_id, port, other_mac, mac, None)
                else:
                    self.del_flow(None, dp_id, port, mac, other_mac, None)
            del flows_list
            del self._mac_flows_dict[mac]
        return

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
        to_be_deleted_list = []
        for index, (dpid, in_port, buffer_id) in enumerate(self.buffers_list):
            try:
                (src, dst, eth_type) = self.pendings_buffer_id[dpid][in_port][buffer_id]
                (buffers, time_stamp) = self.pendings[dpid][in_port][dst][src][eth_type]
                if buffers is not None and time.time() - time_stamp > 60:
                    to_be_deleted_list.append(index)
#                   LOG.info("deleting  expired pending msg %s", buffers)
                    for id in buffers:
                        expired_list.append((dpid, in_port, id))
                        try:
                            del self.pendings_buffer_id[dpid][in_port][id]
                        except:
                            pass
                        try:
                            # it is ok to remove future indexes in the same loop
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
            except:
                pass
        to_be_deleted_list.reverse()
        for id in to_be_deleted_list:
            try:
                del self.buffers_list[id]
            except:
                pass

        return expired_list
