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
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=180, hard_timeout=180,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
    
    def _drop_packet(self, msg):
        datapath = msg.datapath
        #LOG.debug("Dropping packet; Dpid: %s; In port: %s",
        #            datapath.id, msg.in_port)
        datapath.send_packet_out(msg.buffer_id, msg.in_port, [])

    def _handle_arp_packets(self, msg, dst, src, _eth_type):
        self.nw.arp_enabled = True;
	datapath = msg.datapath
	dpid = datapath.id
	#print 'yes. received arp packet.'
        mydata = ctypes.create_string_buffer(42)
        HTYPE, PTYPE, HLEN, PLEN, OPER, SHA, SPA, THA, TPA = struct.unpack_from('!HHbbH6s4s6s4s', buffer(msg.data), 14)
        #print 'HTYPE = %d, PTYPE = %d, HLEN = %d, PLEN = %d, OPER = %d, SHA = %s, SPA = %s, THA = %s, TPA = %s' % (
        #        HTYPE, PTYPE, HLEN, PLEN, OPER, mac.haddr_to_str(SHA), mac.ipaddr_to_str(SPA), mac.haddr_to_str(THA), mac.ipaddr_to_str(TPA))
        dst_ip = SPA
        dst_mac = SHA
        src_ip = TPA
        LOG.info("arp packet: src = %s, dst = %s", mac.ipaddr_to_str(SPA), mac.ipaddr_to_str(TPA))

        try:
            port_nw_id = self.nw.get_network(datapath.id, msg.in_port)
        except PortUnknown:
            port_nw_id = NW_ID_UNKNOWN

        if (port_nw_id == NW_ID_PXE or port_nw_id == NW_ID_PXE_CTRL
           or port_nw_id == NW_ID_MGMT or port_nw_id == NW_ID_MGMT_CTRL):
           #only learn packet for above networks
           if "0.0.0.0" != mac.ipaddr_to_str(SPA):
                LOG.info("arp : learing mac-ip association: mac = %s, ip = %s", mac.haddr_to_str(SHA), mac.ipaddr_to_str(SPA))
                self.mac2port.port_add(datapath, msg.in_port, SHA, SPA)

        #src_mac = self.mac2port.ip_to_mac[datapath.id][TPA]
	if OPER == 1 and TPA in self.mac2port.ip_to_mac:
            src_mac = self.mac2port.ip_to_mac[TPA]
	else:
	    #print 'IP is not registered'
            LOG.info("dropped arp request: %s, %s, %s", dpid, msg.in_port, mac.ipaddr_to_str(SPA))
	    self._drop_packet(msg)
	    return
        # learn a mac address to avoid FLOOD next time.
        #self.mac_to_port[dpid][src] = self.mac2port.mac_to_port[dpid][src]
        #self.mac2port.mac_to_port[dpid][src] = msg.in_port
        struct.pack_into('!6s6sHHHbbH6s4s6s4s', mydata, 0, src, src_mac, _eth_type, HTYPE, PTYPE, HLEN, PLEN, 2, src_mac, src_ip, dst_mac, dst_ip)
        #print '\n\n\n'
        #HTYPE, PTYPE, HLEN, PLEN, OPER, SHA, SPA, THA, TPA = struct.unpack_from('!HHbbH6s4s6s4s', buffer(mydata), 14)
        #print 'HTYPE = %d, PTYPE = %d, HLEN = %d, PLEN = %d, OPER = %d, SHA = %s, SPA = %s, THA = %s, TPA = %s' % (
        #        HTYPE, PTYPE, HLEN, PLEN, OPER, mac.haddr_to_str(SHA), mac.ipaddr_to_str(SPA), mac.haddr_to_str(THA), mac.ipaddr_to_str(TPA))
        
        out_port = msg.in_port
        LOG.info("handled arp packet: %s, %s, %s", dpid, out_port, mac.haddr_to_str(src_mac))
        out_port = msg.in_port
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        datapath.send_packet_out(actions=actions, data=mydata)
        self._drop_packet(msg)
        return


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
	dpid = datapath.id

        dst, src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)

        #br_ex = (datapath.id == 0x80027513556)
	#LOG.info("packet in %s %s %s %s",
        #         dpid, haddr_to_str(src), haddr_to_str(dst), msg.in_port)	

        self.mac_to_port.setdefault(dpid, {})
	
        broadcast = (dst == mac.BROADCAST) or mac.is_multicast(dst)

	# learn a mac address to avoid FLOOD next time.
        if src not in self.mac_to_port[dpid]:
            self.mac_to_port[dpid][src] = msg.in_port
	#self.mac2port.mac_to_port[dpid][dst] = msg.in_port
	
        if  _eth_type != 0x0806:
            return
        #if  broadcast:
        self._handle_arp_packets(msg, dst, src, _eth_type)
	#else:
		#LOG.info("broadcast frame, DROP and install flow (RULE) to the switch")
	#    actions = [] #[datapath.ofproto_parser.OFPActionOutput([])]
	#    self.add_flow(datapath, msg.in_port, _eth_type, dst, actions)	
	#    self._drop_packet(msg)
        return
           
        #if not br_ex and _eth_type != 0x0806:
        if  _eth_type != 0x0806:
            return
        if broadcast:
	    if (_eth_type == 2054): #ARP request
		self._handle_arp_packets(msg, dst, src, _eth_type)
		return
	    else:
		#LOG.info("broadcast frame, DROP and install flow (RULE) to the switch")
		actions = [] #[datapath.ofproto_parser.OFPActionOutput([])]
		self.add_flow(datapath, msg.in_port, _eth_type, dst, actions)	
	    	self._drop_packet(msg)
		return
	elif src != dst:
	    if (dst in self.mac_to_port[dpid]):
                out_port = self.mac_to_port[dpid][dst]
                LOG.info("out_port found %s", out_port)
	        LOG.info("packet in %s %s %s %s",
                    dpid, haddr_to_str(src), haddr_to_str(dst), msg.in_port)	
	    else:
                #LOG.info("out_port not found")
                out_port = ofproto.OFPP_FLOOD	
	else:
	    self._drop_packet(msg)
	    return
	
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        if not broadcast and out_port != ofproto.OFPP_FLOOD and out_port == msg.in_port:
            actions = []
            self.add_flow(datapath, msg.in_port, _eth_type, dst, actions)	
	    self._drop_packet(msg)
	    return
        # install a flow to avoid packet_in next time
        if broadcast or (out_port != ofproto.OFPP_FLOOD):
            LOG.info("install flow: out_port %s ", out_port)
            self.add_flow(datapath, msg.in_port, _eth_type, dst, actions)

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        #if msg.datapath.id != 0x80027513556:
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
