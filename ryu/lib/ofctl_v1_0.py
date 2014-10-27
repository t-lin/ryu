# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
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

import struct
import socket
import logging
import gevent

from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin, haddr_to_str, ALL_MAC, ipaddr_to_bin, ipaddr_to_int,ipaddr_to_str,int2ip
from ryu.lib.dpid import dpid_to_str


LOG = logging.getLogger('ryu.lib.ofctl_v1_0')

DEFAULT_TIMEOUT = 1.0  # TODO:XXX

def to_actions(dp, acts):
    actions = []
    for a in acts:
        action_type = a.get('type')
        if action_type == 'OUTPUT':
            out_port = int(a.get('port', ofproto_v1_0.OFPP_NONE))
            actions.append(dp.ofproto_parser.OFPActionOutput(out_port))
        elif action_type == 'SET_VLAN_VID':
            vlan_vid = int(a.get('vlan_vid', 0xffff))
            actions.append(dp.ofproto_parser.OFPActionVlanVid(vlan_vid))
        elif action_type == 'SET_VLAN_PCP':
            vlan_pcp = int(a.get('vlan_pcp', 0))
            actions.append(dp.ofproto_parser.OFPActionVlanPcp(vlan_pcp))
        elif action_type == 'STRIP_VLAN':
            actions.append(dp.ofproto_parser.OFPActionStripVlan())
        elif action_type == 'SET_DL_SRC':
            dl_src = haddr_to_bin(a.get('dl_src'))
            actions.append(dp.ofproto_parser.OFPActionSetDlSrc(dl_src))
        elif action_type == 'SET_DL_DST':
            dl_dst = haddr_to_bin(a.get('dl_dst'))
            actions.append(dp.ofproto_parser.OFPActionSetDlDst(dl_dst))
        elif action_type == 'SET_NW_DST':
            nw_dst = ipaddr_to_int(a.get('nw_dst'))
            actions.append(dp.ofproto_parser.OFPActionSetNwDst(nw_dst))
        elif action_type == 'SET_NW_SRC':
            nw_src = ipaddr_to_int(a.get('nw_src'))
            actions.append(dp.ofproto_parser.OFPActionSetNwSrc(nw_src))
        elif action_type == 'SET_TP_SRC':
            tp_src = int(a.get('tp_src'))
            actions.append(dp.ofproto_parser.OFPActionSetTpSrc(tp_src))
        elif action_type == 'SET_TP_DST':
            tp_dst = int(a.get('tp_dst'))
            actions.append(dp.ofproto_parser.OFPActionSetTpDst(tp_dst))
        else:
            LOG.debug('Unknown action type')

    return actions


def actions_to_str(acts):
    actions = []
    for a in acts:
        action_type = a.cls_action_type

        if action_type == ofproto_v1_0.OFPAT_OUTPUT:
            buf = 'OUTPUT:' + str(a.port)
        elif action_type == ofproto_v1_0.OFPAT_SET_VLAN_VID:
            buf = 'SET_VLAN_VID:' + str(a.vlan_vid)
        elif action_type == ofproto_v1_0.OFPAT_SET_VLAN_PCP:
            buf = 'SET_VLAN_PCP:' + str(a.vlan_pcp)
        elif action_type == ofproto_v1_0.OFPAT_STRIP_VLAN:
            buf = 'STRIP_VLAN'
        elif action_type == ofproto_v1_0.OFPAT_SET_DL_SRC:
            buf = 'SET_DL_SRC:' + haddr_to_str(a.dl_addr)
        elif action_type == ofproto_v1_0.OFPAT_SET_DL_DST:
            buf = 'SET_DL_DST:' + haddr_to_str(a.dl_addr)
        elif action_type == ofproto_v1_0.OFPAT_SET_NW_DST:
            buf = 'SET_NW_DST:' + int2ip(a.nw_addr)
        elif action_type == ofproto_v1_0.OFPAT_SET_NW_SRC:
            buf = 'SET_NW_SRC:' + int2ip(a.nw_addr)
        elif action_type == ofproto_v1_0.OFPAT_SET_TP_DST:
            buf = 'SET_TP_DST:' + str(a.tp)
        elif action_type == ofproto_v1_0.OFPAT_SET_TP_SRC:
            buf = 'SET_TP_SRC:' + str(a.tp)
        else:
            buf = 'UNKNOWN'
        actions.append(buf)

    return actions


def to_match(dp, attrs):
    ofp = dp.ofproto

    wildcards = ofp.OFPFW_ALL
    in_port = 0
    dl_src = 0
    dl_dst = 0
    dl_vlan = 0
    dl_vlan_pcp = 0
    dl_type = 0
    nw_tos = 0
    nw_proto = 0
    nw_src = 0
    nw_dst = 0
    tp_src = 0
    tp_dst = 0

    for key, value in attrs.items():
        if key == 'in_port':
            in_port = int(value)
            wildcards &= ~ofp.OFPFW_IN_PORT
        elif key == 'dl_src':
            dl_src = haddr_to_bin(value)
            wildcards &= ~ofp.OFPFW_DL_SRC
        elif key == 'dl_dst':
            if value != ALL_MAC:
                dl_dst = haddr_to_bin(value)
                wildcards &= ~ofp.OFPFW_DL_DST
        elif key == 'dl_vlan':
            dl_vlan = int(value)
            wildcards &= ~ofp.OFPFW_DL_VLAN
        elif key == 'dl_vlan_pcp':
            dl_vlan_pcp = int(value)
            wildcards &= ~ofp.OFPFW_DL_VLAN_PCP
        elif key == 'dl_type':
            dl_type = int(value)
            wildcards &= ~ofp.OFPFW_DL_TYPE
        elif key == 'nw_tos':
            nw_tos = int(value)
            wildcards &= ~ofp.OFPFW_NW_TOS
        elif key == 'nw_proto':
            nw_proto = int(value)
            wildcards &= ~ofp.OFPFW_NW_PROTO
        elif key == 'nw_src':
            ip = value.split('/')
            nw_src = struct.unpack('!I', socket.inet_aton(ip[0]))[0]
            mask = 32
            if len(ip) == 2:
                mask = int(ip[1])
                assert 0 < mask <= 32
            v = (32 - mask) << ofp.OFPFW_NW_SRC_SHIFT | \
                ~ ofp.OFPFW_NW_SRC_MASK
            wildcards &= v
        elif key == 'nw_dst':
            ip = value.split('/')
            nw_dst = struct.unpack('!I', socket.inet_aton(ip[0]))[0]
            mask = 32
            if len(ip) == 2:
                mask = int(ip[1])
                assert 0 < mask <= 32
            v = (32 - mask) << ofp.OFPFW_NW_DST_SHIFT | \
                ~ ofp.OFPFW_NW_DST_MASK
            wildcards &= v
        elif key == 'tp_src':
            tp_src = int(value)
            wildcards &= ~ofp.OFPFW_TP_SRC
        elif key == 'tp_dst':
            tp_dst = int(value)
            wildcards &= ~ofp.OFPFW_TP_DST
        else:
            LOG.debug("unknown match name %s, %s, %d", key, value, len(key))

    match = dp.ofproto_parser.OFPMatch(
        wildcards, in_port, dl_src, dl_dst, dl_vlan, dl_vlan_pcp,
        dl_type, nw_tos, nw_proto, nw_src, nw_dst, tp_src, tp_dst)

    return match


def match_to_str(m):
    return {'dl_dst': haddr_to_str(m.dl_dst),
            'dl_src': haddr_to_str(m.dl_src),
            'dl_type': m.dl_type,
            'dl_vlan': m.dl_vlan,
            'dl_vlan_pcp': m.dl_vlan_pcp,
            'in_port': m.in_port,
            'nw_dst': socket.inet_ntoa(struct.pack('!I', m.nw_dst)),
            'nw_proto': m.nw_proto,
            'nw_src': socket.inet_ntoa(struct.pack('!I', m.nw_src)),
            'tp_src': m.tp_src,
            'tp_dst': m.tp_dst}


def send_stats_request(dp, stats, waiters, msgs):
    dp.set_xid(stats)
    waiters.setdefault(dp.id, {})
    lock = gevent.event.AsyncResult()
    # print 'Stats %s', str(stats.xid)
    waiters[dp.id][stats.xid] = (lock, msgs)
    # print "send stats %s, %s" % (dp.id, stats.xid)
    dp.send_msg(stats)

    try:
        lock.get(timeout = DEFAULT_TIMEOUT)
    except gevent.Timeout:
        del waiters[dp.id][stats.xid]
        # print "deleted stats %s, %s" % (dp.id, stats.xid)

def get_desc_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPDescStatsRequest(dp, 0)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    s = None
    desc = {}
    for msg in msgs:
        stats = msg.body
        s = {'mfr_desc': stats.mfr_desc,
             'hw_desc': stats.hw_desc,
             'sw_desc': stats.sw_desc,
             'serial_num': stats.serial_num,
             'dp_desc': stats.dp_desc}
#    desc = {str(dp.id): s}
    if s:
        desc = {dpid_to_str(dp.id): s}
    return desc


def get_flow_stats(dp, flow, waiters):
    match = to_match(dp, flow.get('match', {}))
    # match = dp.ofproto_parser.OFPMatch(
    #    dp.ofproto.OFPFW_ALL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    stats = dp.ofproto_parser.OFPFlowStatsRequest(
        dp, 0, match, 0xff, dp.ofproto.OFPP_NONE)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    flows = []
    for msg in msgs:
        for stats in msg.body:
            actions = actions_to_str(stats.actions)
            match = match_to_str(stats.match)

            s = {'priority': stats.priority,
                 'cookie': stats.cookie,
                 'idle_timeout': stats.idle_timeout,
                 'hard_timeout': stats.hard_timeout,
                 'actions': actions,
                 'match': match,
                 'byte_count': stats.byte_count,
                 'duration_sec': stats.duration_sec,
                 'duration_nsec': stats.duration_nsec,
                 'packet_count': stats.packet_count,
                 'table_id': stats.table_id}
            flows.append(s)
#    flows = {str(dp.id): flows}
    flows = {dpid_to_str(dp.id): flows}
    return flows


def get_port_stats(dp, waiters):
    stats = dp.ofproto_parser.OFPPortStatsRequest(
        dp, 0, dp.ofproto.OFPP_NONE)
    msgs = []
    send_stats_request(dp, stats, waiters, msgs)

    ports = []
    for msg in msgs:
        for stats in msg.body:
            s = {'port_no': stats.port_no,
                 'rx_packets': stats.rx_packets,
                 'tx_packets': stats.tx_packets,
                 'rx_bytes': stats.rx_bytes,
                 'tx_bytes': stats.tx_bytes,
                 'rx_dropped': stats.rx_dropped,
                 'tx_dropped': stats.tx_dropped,
                 'rx_errors': stats.rx_errors,
                 'tx_errors': stats.tx_errors,
                 'rx_frame_err': stats.rx_frame_err,
                 'rx_over_err': stats.rx_over_err,
                 'rx_crc_err': stats.rx_crc_err,
                 'collisions': stats.collisions}
            ports.append(s)
#    ports = {str(dp.id): ports}
    ports = {dpid_to_str(dp.id): ports}
    return ports


def mod_flow_entry(dp, flow, cmd):
    if flow.get('cookie', 0):
       cookie = int(flow.get('cookie', 0))
    else:
       cookie = 0

    priority = int(flow.get('priority',
                            dp.ofproto.OFP_DEFAULT_PRIORITY))
    flags = int(flow.get('flags', 0))
    idle_timeout = int(flow.get('idle_timeout', 0))
    hard_timeout = int(flow.get('hard_timeout', 0))
    actions = to_actions(dp, flow.get('actions', {}))
    match = to_match(dp, flow.get('match', {}))
    out_port = int(flow.get('out_port', ofproto_v1_0.OFPP_NONE))

    flow_mod = dp.ofproto_parser.OFPFlowMod(
        datapath = dp, match = match, cookie = cookie,
        command = cmd, idle_timeout = idle_timeout,
        hard_timeout = hard_timeout, priority = priority,
        out_port = out_port, flags = flags, actions = actions)

    dp.send_msg(flow_mod)


def delete_flow_entry(dp):
    match = dp.ofproto_parser.OFPMatch(
        dp.ofproto.OFPFW_ALL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    flow_mod = dp.ofproto_parser.OFPFlowMod(
        datapath = dp, match = match, cookie = 0,
        command = dp.ofproto.OFPFC_DELETE)

    dp.send_msg(flow_mod)

def send_features_request(dp, features, waiters, msgs):
    dp.set_xid(features)
    waiters = waiters.setdefault(dp.id, {})
    lock = gevent.event.AsyncResult()
    waiters[features.xid] = (lock, msgs)
    dp.send_msg(features)

    try:
        lock.get(timeout = DEFAULT_TIMEOUT)
    except gevent.Timeout:
        del waiters[dp.id][features.xid]


def get_features(dp, waiters):
    # print 'Waiters %s' % str(waiters)
    features = dp.ofproto_parser.OFPFeaturesRequest(dp)
    # print 'feature requested %s' % str(features.xid)
    msgs = []
    send_features_request(dp, features, waiters, msgs)

    for msg in msgs:
        s = msg.body
# print msg
#    feature = {str(dp.id): s}
    feature = {dpid_to_str(dp.id): s}
    return feature


