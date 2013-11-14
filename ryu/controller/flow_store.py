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
import socket, struct

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
        self._dhcp_mac_list = {}
        self._mac_flows_dict = {}
        self._user_flows = {}

    def _actions_equal(self, acts1, acts2):
        try:
            if len(acts1) != len(acts2):
                return False
            for index, act in enumerate(acts1):
                type = act.get('type', None)
                if type != acts2[index].get('type', 1):
                    return False
                if type == 'OUTPUT':
                    if act.get('port', -1) != acts2[index].get('port', -2):
                        return False
                elif type == 'SET_DL_DST':
                    if act.get('dl_dst', -1) != acts2[index].get('dl_dst', -2):
                        return False
                elif type == 'SET_DL_SRC':
                    if act.get('dl_src', -1) != acts2[index].get('dl_src', -2):
                        return False
                elif type == 'SET_NW_SRC':
                    if act.get('nw_src', -1) != acts2[index].get('nw_src', -2):
                        return False
                elif type == 'SET_NW_DST':
                    if act.get('nw_dst', -1) != acts2[index].get('nw_dst', -2):
                        return False
                elif type == 'SET_TP_SRC':
                    if act.get('tp_src', -1) != acts2[index].get('tp_src', -2):
                        return False
                elif type == 'SET_TP_DST':
                    if act.get('tp_dst', -1) != acts2[index].get('tp_dst', -2):
                        return False
                else:
                    LOG.warn("unknown action in actions_equal %s", type)
                    return False
            return True
        except:
            return False

    def del_port(self, dpid, port_no):
        pass
        """
        dp_dict = self._dps.get(dpid, None)
        if dp_dict is not None:
            in_port_dict = dp_dict.get(port_no, None)
            if in_port_dict is not None:
                del dp_dict[port_no]
        """

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

    def addressInNetwork(self, ipaddr, net):
       "Is an address in a network"
       # ipaddr = struct.unpack('L', socket.inet_aton(ip))[0]
       try:
           netaddr, bits = net.split('/')
           netmask = struct.unpack('<L', socket.inet_aton(netaddr))[0] & ((2L << int(bits) - 1) - 1)
           return ipaddr & netmask == netmask
       except:
           traceback.print_exc()
           return False

    def _compare_extra_match(self, ex_match, extra_match):
        if ex_match is None and extra_match is not None:
            return False
        if extra_match is None and ex_match is not None:
            return False
        if extra_match is None and ex_match is None:
            return True

        for key in 'nw_proto', 'nw_src', 'nw_dst', 'tp_src', 'tp_dst':
            if ex_match.get(key, None) != extra_match.get(key, None):
                return False

        return True

    def _match_equal(self, extra_match, nw_proto, nw_src, nw_dst, tp_src, tp_dst):
        nw_p = extra_match.get('nw_proto', None)
        nw_s = extra_match.get('nw_src', None)
        nw_d = extra_match.get('nw_dst', None)
        tp_s = extra_match.get('tp_src', None)
        tp_d = extra_match.get('tp_dst', None)

        if  nw_p != None and nw_p != nw_proto:
            return False
        if  nw_s != None and not self.addressInNetwork(nw_src, nw_s):
            return False
        if  nw_d != None and not self.addressInNetwork(nw_dst, nw_d):
            return False
        if  tp_s != None and tp_s != tp_src:
            return False
        if  tp_d != None and tp_d != tp_dst:
            return False

        return True


    def get_all_flows(self, dpid = None):
        if dpid is None:
            return self._dps
        return self._dps.get(dpid, {})

    def get_user_flows(self, dpid = None, user_id = None, req_id = None):
        if dpid is None:
            return self._user_flows
        u_dict = self._user_flows.get(dpid, None)
        if u_dict is None:
            return {}
        r_dict = {}
        delete_item = []
        if user_id is not None and req_id is not None:
            (in_port, dest, src, eth_type, src_mac_list) = u_dict.get(int(req_id), (None, None, None, None, None))
            if in_port is not None:
                for (pr, id, eth_t, acts, out_ports, idle_timeout, hard_timeout, nums, u_id, extra_match) in src_mac_list:
                    if u_id is not None:
                        if user_id != u_id or int(req_id) != id:
                            continue
                        r_dict[id] = (in_port, dest, src, eth_t, pr, acts, out_ports, idle_timeout, hard_timeout, u_id, extra_match)
                        break
            return r_dict

        for id, (in_port, dest, src, eth_type, src_mac_list) in u_dict.iteritems():
            if src_mac_list is None or len(src_mac_list) == 0:
                delete_ietm.append(id)
                continue
            for (pr, id, eth_t, acts, out_ports, idle_timeout, hard_timeout, nums, u_id, extra_match) in src_mac_list:
                if u_id is not None:
                    if user_id is not None and user_id != u_id:
                        continue
                    r_dict[id] = (in_port, dest, src, eth_t, pr, acts, out_ports, idle_timeout, hard_timeout, u_id, extra_match)
        for id in delete_item:
            del u_dict[id]
        return r_dict

    def get_flow(self, dpid, in_port, src, dst, eth_type, nw_proto = None, nw_src = None, nw_dst = None, tp_src = None, tp_dst = None):
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
        for index, (pr, id, eth_t, acts, out_ports, idle_timeout, hard_timeout, nums, user_id, extra_match) in enumerate(src_mac_list):
            if eth_t is None or eth_type == eth_t:
                if extra_match is not None:
                    if not self._match_equal(extra_match, nw_proto, nw_src, nw_dst, tp_src, tp_dst):
                        continue
                LOG.info("found : %s,%s,%s,%s,%s,%s" % (pr, eth_t, acts, out_ports, idle_timeout, hard_timeout))
                return (id, pr, eth_t, acts, out_ports, idle_timeout, hard_timeout, with_source)

        with_source = 0
        src_mac_list = dest_mac_dict.get('0', [])
        for index, (pr, id, eth_t, acts, out_ports, idle_timeout, hard_timeout, nums, user_id, extra_match) in enumerate(src_mac_list):
            if eth_t is None or eth_type == eth_t:
                if extra_match is not None:
                    if not self._match_equal(extra_match, nw_proto, nw_src, nw_dst, tp_src, tp_dst):
                        continue
                ret = (id, pr, eth_t, acts, out_ports, idle_timeout, hard_timeout, with_source)
                LOG.info("found : %s" % (ret,))
                return ret

        return (None, None, None, None, None, None, None, None)

    def add_dhcp_flow(self, dpid, in_port, src, actions):
        self._dhcp_flow.setdefault(dpid, {})
        self._dhcp_flow[dpid].setdefault(in_port, {})
        self._dhcp_flow[dpid][in_port][src] = actions
        self._dhcp_mac_list[src] = (dpid, in_port)
        return

    def del_dhcp_flow(self, src):
        try:
            (d_id, port) = self._dhcp_mac_list.pop(src, (None, None))
            if d_id and port:
                del self._dhcp_flow[d_id][port][src]
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
        user_id = flow.get('user_id', None)
        if user_id is None and match.get('tp_src', 0) == 68 and eth_type == 0x800:
            # this is a dhcp flow, no need to add to store
            self.add_dhcp_flow(dpid, in_port, src, actions)
            return

        out_port = flow.get('out_port', ofproto_v1_0.OFPP_NONE)
        idle_timeout = flow.get('idle_timeout', 0)
        hard_timeout = flow.get('hard_timeout', 0)

        extra_match = {}
        for key, val in match.iteritems():
            if key in ('tp_src', 'tp_dst', 'nw_src', 'nw_dst', 'nw_proto'):
                    extra_match[key] = val
        if len(extra_match) == 0:
            extra_match = None

        if dpid is not None and dest is not None:
            return self.add_flow(api_db, dpid, in_port, dest, src, eth_type, actions, priority, out_port, idle_timeout, hard_timeout, user_id = user_id, extra_match = extra_match)
        return -1

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

    def del_user_flow(self, api_db, dpid, user_id, id):
        i_dpid = int(dpid, 16)
        ret = (None, None, None, None, None, None, None)
        if api_db is not None and user_id is not None and id is not None:
            user_dict = self._user_flows.get(i_dpid, {})
            (in_port, dest, src, eth_type, src_mac_list) = user_dict.pop(id, (None, None, None, None, None))
            if src_mac_list is not None and len(src_mac_list) > 0:
                for index, (pr, id1, eth_t, acts, o, i1, j1, nums, u_id, extra_match) in enumerate(src_mac_list):
                    if id1 == id and user_id == u_id:
                        del src_mac_list[index]
                        ret = (i_dpid, pr, in_port, src, dest, eth_type, extra_match)
                        break
                if len(src_mac_list) == 0:
                    self.del_flow(api_db, i_dpid, in_port, dest, src, eth_type)
            if len(user_dict) == 0:
                self._user_flows.pop(i_dpid, None)
            if api_db is not None:
                api_db.del_user_flow(i_dpid, user_id, id)
        return ret

    def add_flow(self, api_db, dpid, in_port, dest, src, eth_type, actions, priority, out_port, idle_timeout, hard_timeout, in_id = -1, user_id = None, extra_match = None):
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

        id = -1
        if len(src_mac_list) > 0:
            for index, (pr, id1, eth_t, acts, o, i1, j1, nums, u_id, ex_match) in enumerate(src_mac_list):
                if eth_type is not None and eth_type != eth_t:
                    continue
                if priority == pr and self._actions_equal(acts, actions) and user_id == u_id:
                    if extra_match is not None or ex_match is not None:
                        if self._compare_extra_match(ex_match, extra_match) is False:
                            continue
                    ret = False
                    src_mac_list[index] = (pr, id1, eth_t, acts, out_port, idle_timeout, hard_timeout, nums + 1, u_id, ex_match)
                    id = id1
#                    LOG.info("updated : %s,%s,%s,\%s,%s,%s,%s" % (priority, eth_t, actions, out_port, idle_timeout, hard_timeout, nums + 1))
                    break

        if ret:
            if api_db is not None:
                try:
                    id = api_db.add_flow(str(hex(dpid)), in_port, dest, src, priority, eth_type, actions, out_port, idle_timeout, hard_timeout, user_id, extra_match)
                except:
                    id = -1
                    raise
            else:
                id = in_id

            if id > self.dpid_ids.get(dpid, 0):
                self.dpid_ids[dpid] = id
            self.dpid_nums[dpid] = self.dpid_nums.get(dpid, 0) + 1
            src_mac_list.append((priority, id, eth_type, actions, out_port, idle_timeout, hard_timeout, 1, user_id, extra_match))
            src_mac_list.reverse()
            if id > 0 and user_id is not None:
                self._user_flows.setdefault(dpid, {})
                self._user_flows[dpid][id] = (in_port, dest, src, eth_type, src_mac_list)
            if src is not None:
                self.add_mac_flow(dpid, in_port, src, True, dest)
            self.add_mac_flow(dpid, in_port, dest, False, src)
 #          LOG.info("added : %s,%s,%s,%s,%s,%s,%s" % (priority, eth_type, actions, out_port, idle_timeout, hard_timeout, 1))

        return id

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
                    for index, (pr, id, eth_t, acts, out_ports, idle_timeout, hard_timeout, nums, user_id, extra_match) in enumerate(src_mac_list):
                        if eth_type is not None and eth_t != eth_type:
                            continue
                        src_mac_list[index] = (pr, id, eth_t, acts, out_ports, idle_timeout, hard_timeout, nums - 1, user_id, extra_match)
                        found = True
#                        if (nums - 1) == 0:
                        ret = True
                        index_to_be_removed.append(index)
                        self.dpid_nums[dpid] = self.dpid_nums[dpid] - 1
                        if api_db and id != -1:
                            try:
                                api_db.del_flow(str(hex(dpid)), in_p, dst, id)
                            except:
                                traceback.print_exc()
                                pass
                        if user_id != None and id > 0:
                            self._user_flows.setdefault(dpid, {})
                            self._user_flows[dpid].pop(id, None)
                            if len(self._user_flows[dpid]) == 0:
                                del self._user_flows[dpid]
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

        if not found:
            ret = True

        return ret

    def add_mac_flow(self, dpid, port, mac, src_or_dst, other_mac):
        flows_list = self._mac_flows_dict.setdefault(mac, [])
        flows_list.append((dpid, port, src_or_dst, other_mac))
        return

    def del_mac_flows(self, mac):
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
