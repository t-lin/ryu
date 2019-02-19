# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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
import struct
import os

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import nx_match
from ryu.lib.mac import haddr_to_str
from ryu.lib import mac
from ryu.demo import demo_app

LOG = logging.getLogger('ryu.app.simple_switch')

# TODO: we should split the handler into two parts, protocol
# independent and dependant parts.

# TODO: can we use dpkt python library?

# TODO: we need to move the followings to something like db


class SimpleSwitch(app_manager.RyuApp):
    _CONTEXTS = {
        'mac2port': mac_to_port.MacToPortTable,
        }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac2port = {}
        self._demo_app = None
        self._last_demo_change = 0

    def _drop_packet(self, msg):
        if msg.buffer_id != 0xffffffff:
            datapath = msg.datapath
            datapath.send_packet_out(msg.buffer_id, msg.in_port, [])

    def _is_demo_app_changed(self):
        stat = os.stat(demo_app.__file__)
        if self._last_demo_change < stat.st_mtime:
            self._last_demo_change = stat.st_mtime
            return True

        return False

    def demo_app(self):
        if not self._demo_app or self._is_demo_app_changed():
            reload(demo_app)
            print "\n***\nReloading application\n***\n"
            appObjs = {'mac2port': self.mac2port}
            self._demo_app = demo_app.DemoApp(appObjs)

        return self._demo_app

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.demo_app().handle_packet_in(ev)

        '''
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        dst, src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)

        dpid = datapath.id
        self.mac2port.dpid_add(dpid)
        LOG.info("packet in %s %s %s %s",
                 dpid, haddr_to_str(src), haddr_to_str(dst), msg.in_port)

        self.mac2port.port_add(dpid, msg.in_port, src)
	broadcast = (dst == mac.BROADCAST) or mac.is_multicast(dst)

        if broadcast:
		out_port = ofproto.OFPP_FLOOD
         	LOG.info("broadcast frame, flood and install flow")
	else:
		if src != dst:
			out_port = self.mac2port.port_get(dpid, dst)
	        	if out_port == None:
         			LOG.info("out_port not found")
				out_port = ofproto.OFPP_FLOOD
		else:
			self._drop_packet(msg)
			return

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        rule = nx_match.ClsRule()
        rule.set_in_port(msg.in_port)
        rule.set_dl_dst(dst)
        rule.set_dl_src(src)
        rule.set_nw_dscp(0)
        datapath.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

        datapath.send_packet_out(msg.buffer_id, msg.in_port, actions)
        '''

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        ofproto = msg.datapath.ofproto

        if reason == ofproto.OFPPR_ADD:
		port_no = msg.desc.port_no
        	LOG.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
		port_no = msg.desc.port_no
        	LOG.info("port deleted %s", port_no)
        else:
		port_no = msg.desc.port_no
        	LOG.info("port modified %s", port_no)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_replay_handler(self, ev):
        pass
