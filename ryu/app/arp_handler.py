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
import ctypes


from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_str
from ryu.lib import mac
from ryu.controller import network
from ryu.app.rest_nw_id import NW_ID_UNKNOWN, NW_ID_EXTERNAL
from ryu.app.rest_nw_id import NW_ID_PXE_CTRL, NW_ID_PXE, NW_ID_MGMT_CTRL, NW_ID_MGMT


LOG = logging.getLogger('ryu.app.arp_handler')

# TODO: we should split the handler into two parts, protocol
# independent and dependant parts.

# TODO: can we use dpkt python library?

# TODO: we need to move the followings to something like db


class ArpHandler(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    _CONTEXTS = {
        'network': network.Network,
        'mac2port': mac_to_port.MacToPortTable
    }

    def __init__(self, *args, **kwargs):
        super(ArpHandler, self).__init__(*args, **kwargs)
        self.mac2port = kwargs['mac2port']
        self.nw = kwargs['network']
        self.mac_to_port = {}
        self.nw.arp_enabled = True;

    def add_flow(self, datapath, in_port, eth_type, dst, actions):
        ofproto = datapath.ofproto

        wildcards = ofproto_v1_0.OFPFW_ALL
        wildcards &= ~ofproto_v1_0.OFPFW_IN_PORT
        wildcards &= ~ofproto_v1_0.OFPFW_DL_DST
        wildcards &= ~ofproto_v1_0.OFPFW_DL_TYPE

        match = datapath.ofproto_parser.OFPMatch(
            wildcards, in_port, 0, dst,
            0, 0, eth_type, 0, 0, 0, 0, 0, 0)

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath = datapath, match = match, cookie = 0,
            command = ofproto.OFPFC_ADD, idle_timeout = 180, hard_timeout = 180,
            priority = ofproto.OFP_DEFAULT_PRIORITY,
            flags = ofproto.OFPFF_SEND_FLOW_REM, actions = actions)
        datapath.send_msg(mod)

    def _drop_packet(self, msg):
        datapath = msg.datapath
        # LOG.debug("Dropping packet; Dpid: %s; In port: %s",
        #            datapath.id, msg.in_port)
        datapath.send_packet_out(msg.buffer_id, msg.in_port, [])

    def _handle_arp_packets(self, msg, dst, src, _eth_type):       
        self.nw.arp_enabled = True;
    	datapath = msg.datapath
    	dpid = datapath.id
	# print 'yes. received arp packet.'
        mydata = ctypes.create_string_buffer(42)
        HTYPE, PTYPE, HLEN, PLEN, OPER, SHA, SPA, THA, TPA = struct.unpack_from('!HHbbH6s4s6s4s', buffer(msg.data), 14)
        # print 'HTYPE = %d, PTYPE = %d, HLEN = %d, PLEN = %d, OPER = %d, SHA = %s, SPA = %s, THA = %s, TPA = %s' % (
        #        HTYPE, PTYPE, HLEN, PLEN, OPER, mac.haddr_to_str(SHA), mac.ipaddr_to_str(SPA), mac.haddr_to_str(THA), mac.ipaddr_to_str(TPA))
        self._drop_packet(msg)
        if OPER != 1:
            return False
        dst_ip = SPA
        dst_mac = SHA
        src_ip = TPA
        LOG.info("arp packet: src = %s, dst = %s", mac.ipaddr_to_str(SPA), mac.ipaddr_to_str(TPA))

        src_mac = self.mac2port.mac_ip_get(src_ip)
        if src_mac is not None:
            struct.pack_into('!6s6sHHHbbH6s4s6s4s', mydata, 0, src, src_mac, _eth_type, HTYPE, PTYPE, HLEN, PLEN, 2, src_mac, src_ip, dst_mac, dst_ip)
    
            out_port = msg.in_port
            LOG.info("handled arp packet: %s, %s, %s", dpid, out_port, mac.haddr_to_str(src_mac))
            out_port = msg.in_port
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            datapath.send_packet_out(actions = actions, data = mydata)
            return True
        return False


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        dpid = datapath.id

        dst, src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)

        if  dst != mac.BROADCAST or _eth_type != 0x0806:
           return
        # if  broadcast:
        # if not br_ex and _eth_type != 0x0806:
        if self._handle_arp_packets(msg, dst, src, _eth_type) is False:
            #pass to janus, we donot know waht to do
        return

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        # if msg.datapath.id != 0x80027513556:
        #    return

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            LOG.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            LOG.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            LOG.info("port modified %s", port_no)
        else:
            LOG.info("Illeagal port state %s %s", port_no, reason)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_replay_handler(self, ev):
        pass
