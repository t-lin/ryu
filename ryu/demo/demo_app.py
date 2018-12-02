import logging
import struct
import os

from ryu.app.rest_nw_id import NW_ID_UNKNOWN, NW_ID_EXTERNAL
from ryu.base import app_manager
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import nx_match
from ryu.lib.mac import haddr_to_str
from ryu.lib.lldp import ETH_TYPE_LLDP
from ryu.lib import mac


LOG = logging.getLogger('ryu.demo.demo_app')

class DemoApp(object):
    def __init__(self, appObjs):
        self.mac2port = appObjs['mac2port'] # Dictionary of dictionaries

    def _drop_packet(self, msg):
        if msg.buffer_id != 0xffffffff:
            LOG.info("Dropping packet")
            datapath = msg.datapath
            datapath.send_packet_out(msg.buffer_id, msg.in_port, [])

    def handle_packet_in(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        dst, src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)

        # In case this app is used in conjunction with the topology discovery
        # app, we should ignore all LLDP packets
        if _eth_type == ETH_TYPE_LLDP:
            return

        dpid = datapath.id # Switch ID
        self.mac2port.setdefault(dpid, {})  # Create new record for this switch
                                            # if it didn't exist before
        LOG.info("Src MAC: %s; Dest MAC: %s", haddr_to_str(src), haddr_to_str(dst))

        self.mac2port[dpid][src] = msg.in_port  # Save record of port number
                                                # associated with MAC address
        broadcast = (dst == mac.BROADCAST) or mac.is_multicast(dst)

        if broadcast:
            out_port = ofproto.OFPP_FLOOD
            LOG.info("broadcast frame, flood and install flow")
        else:
            if src != dst:
                # Fetch port number associated with destination MAC
                # Return None if no record exists
                out_port = self.mac2port[dpid].get(dst, None)
                if out_port == None:
                    LOG.info("Output port not found")
                    out_port = ofproto.OFPP_FLOOD
            else:
                self._drop_packet(msg)
                return

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        LOG.info("Input port: %s; Output port: %s", msg.in_port, out_port)

        rule = nx_match.ClsRule()
        rule.set_in_port(msg.in_port)
        rule.set_dl_dst(dst)
        rule.set_dl_src(src)
        rule.set_nw_dscp(0)
        datapath.send_flow_mod(
            rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=60, hard_timeout=60,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

        if msg.buffer_id == 0xffffffff:
            # Switch didn't buffer packet, whole packet was sent to controller
            datapath.send_packet_out(msg.buffer_id, msg.in_port, actions, data = msg.data)
        else:
            datapath.send_packet_out(msg.buffer_id, msg.in_port, actions)



