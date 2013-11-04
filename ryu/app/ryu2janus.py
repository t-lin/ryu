# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (C) 2013, The SAVI Project.
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
import httplib
import json
import gflags
import ctypes
import gevent

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.controller import flow_store
from ryu.controller import api_db
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_str, ipaddr_to_str, is_multicast
from ryu.lib.lldp import ETH_TYPE_LLDP, LLDP_MAC_NEAREST_BRIDGE
from janus.network.of_controller.janus_of_consts import JANEVENTS, JANPORTREASONS
from janus.network.of_controller.event_contents import EventContents
from dpkt.ntp import BROADCAST
from ryu.ofproto import nx_match, inet
from ryu.lib import mac, ofctl_v1_0
from netaddr import IPAddress

FLAGS = gflags.FLAGS
gflags.DEFINE_string('janus_host', '127.0.0.1', 'Janus host IP address')
gflags.DEFINE_integer('janus_port', '8091', 'Janus admin API port')

LOG = logging.getLogger('ryu.app.ryu2janus')

OFI_ETH_TYPE_IP = 2048
OFI_ETH_TYPE_ARP = 0x806
OFI_UDP = 17
BOOTP_CLIENT_PORT_PORT_NUMBER = 68
OFP_DEFAULT_PRIORITY = 0x8000

class Ryu2JanusForwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'flow_store': flow_store.FlowStore,
        'api_db': api_db.API_DB,
        'mac2port': mac_to_port.MacToPortTable,
    }

    def __init__(self, *args, **kwargs):
        super(Ryu2JanusForwarding, self).__init__(*args, **kwargs)
        self.mac2port = kwargs['mac2port']
        self.dpset = kwargs['dpset']
        self.api_db = kwargs.get('api_db', None)

        # Janus address
        self._conn = None
        self.host = FLAGS.janus_host
        self.port = FLAGS.janus_port
        self.url_prefix = '/v1.0/events/0'
        self.flow_store = kwargs['flow_store']
        self.is_active = True
        self.threads = []
        self.threads.append(gevent.spawn_later(0, self.cleaning_loop))

    def close(self):
        self.is_active = False
        # gevent.killall(self.threads)
        gevent.joinall(self.threads)

    def _install_modflow(self, msg, in_port, src, dst = None, eth_type = None, actions = None,
                         priority = OFP_DEFAULT_PRIORITY,
                         idle_timeout = 0, hard_timeout = 0):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        if LOG.getEffectiveLevel() == logging.DEBUG:
            if len(actions) > 0:
                act = "out to "
                for action in actions:
                    act += str(action.port) + ","
            else:
                act = "drop"
            LOG.debug("installing flow from port %s, src %s to dst %s, action %s", msg.in_port, haddr_to_str(src), haddr_to_str(dst), act)
        if actions is None:
            actions = []

        # install flow
        rule = nx_match.ClsRule()
        if in_port is not None:
            rule.set_in_port(in_port)
        if dst is not None:
            rule.set_dl_dst(dst)
        if src is not None:
            rule.set_dl_src(src)
        if eth_type is not None:
            rule.set_dl_type(eth_type)

        datapath.send_flow_mod(
            rule = rule, cookie = 0, command = datapath.ofproto.OFPFC_ADD,
            idle_timeout = idle_timeout, hard_timeout = hard_timeout,
            priority = priority,
            buffer_id = 0xffffffff, out_port = ofproto.OFPP_NONE,
            flags = ofproto.OFPFF_SEND_FLOW_REM, actions = actions)

    def _modflow_and_drop_packet(self, msg, src, dst, priority = OFP_DEFAULT_PRIORITY, idle_timeout = 0):
        LOG.info("installing flow for dropping packet")
        datapath = msg.datapath
        in_port = msg.in_port

        self._install_modflow(msg, in_port, src, dst, actions = [], priority = priority, idle_timeout = idle_timeout)
        datapath.send_packet_out(msg.buffer_id, in_port, [])

    def _forward2Controller(self, method, url, body = None, headers = None):

        try:
            self._conn.request(method, url, body, headers)
            res = self._conn.getresponse()
            res.read()
        except:
            try:
                LOG.info("Failed to Send to Janus first time: %s, %s, body = %s", method, url, body)
                self._conn = httplib.HTTPConnection(self.host, self.port)
                self._conn.request(method, url, body, headers)
                res = self._conn.getresponse()
                res.read()
            except:
                LOG.warning("Failed to Send to Janus: body = %s", body)
                return
            pass
        print "\n"
        if res.status in (httplib.OK,
                          httplib.CREATED,
                          httplib.ACCEPTED,
                          httplib.NO_CONTENT):
            return res

        raise httplib.HTTPException(
            res, 'code %d reason %s' % (res.status, res.reason),
            res.getheaders(), res.read())


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.flow_store.del_port(msg.datapath.id, port_no)
            LOG.info("port added %s", port_no)
            reason_id = JANPORTREASONS.JAN_PORT_ADD
            method = 'POST'
        elif reason == ofproto.OFPPR_DELETE:
            self.flow_store.del_port(msg.datapath.id, port_no)
            LOG.info("port deleted %s", port_no)
            reason_id = JANPORTREASONS.JAN_PORT_DELETE
            method = 'PUT'  # 'DELETE' doesn't support a body in the request
        elif reason == ofproto.OFPPR_MODIFY:
            LOG.info("port modified %s", port_no)
            reason_id = JANPORTREASONS.JAN_PORT_MODIFY
            method = 'PUT'
        else:
            LOG.info("Illegal port state %s %s", port_no, reason)
            LOG.info("UNKNOWN PORT STATUS REASON")
            raise

        # TO DO: Switch to using EventContents class
        body = json.dumps({'event': {'of_event_id': JANEVENTS.JAN_EV_PORTSTATUS,
                                        'datapath_id': msg.datapath.id,
                                        'reason': reason_id, 'port': port_no}})
        header = {"Content-Type": "application/json"}

        url = self.url_prefix
        LOG.info("FORWARDING PORT STATUS TO JANUS: body = %s", body)
        self._forward2Controller(method, url, body, header)

    def _packet_not_dhcp_request(self, dp, dpid, in_port, buffer_id, dl_dst, dl_src, eth_type, data):
        if dl_dst == mac.BROADCAST and eth_type == 0x800:
            dummy1, ip_proto, dummy2, src_ip, dst_ip = struct.unpack_from('!BBHLL', buffer(data), 22)
            if ip_proto == inet.IPPROTO_UDP:
                tp_sport, tp_dport = struct.unpack_from('!HH', buffer(data), 34)
                if tp_sport == 68:
                    actions = self.flow_store.get_dhcp_flow(dpid, in_port, haddr_to_str(dl_src))
                    if actions is not None:
                        LOG.info("dhcp packet handled (%s, %s), (%s), %s -> %s", hex(dpid), in_port,
                                 haddr_to_str(dl_src), str(IPAddress(src_ip)), str(IPAddress(dst_ip)))
                        flow = {}
                        flow['in_port'] = in_port
                        flow['dl_dst'] = 'ff:ff:ff:ff:ff:ff'
                        flow['dl_src'] = haddr_to_str(dl_src)
                        flow['dl_type'] = OFI_ETH_TYPE_IP
                        flow['nw_proto'] = inet.IPPROTO_UDP
#                        flow['nw_dst'] = "0.0.0.0/32"
                        flow['tp_src'] = BOOTP_CLIENT_PORT_PORT_NUMBER
                        match = ofctl_v1_0.to_match(dp, flow)
                        priority = OFP_DEFAULT_PRIORITY + 30000
                        acts = ofctl_v1_0.to_actions(dp, actions)
                        out_port = int(flow.get('out_port', ofproto_v1_0.OFPP_NONE))
                        flow_mod = dp.ofproto_parser.OFPFlowMod(
                            datapath = dp, match = match, cookie = 0,
                            command = dp.ofproto.OFPFC_ADD, idle_timeout = 0,
                            hard_timeout = 0, priority = priority,
                            flags = 0, actions = acts, out_port = out_port)

                        dp.send_msg(flow_mod)
                        dp.send_packet_out(buffer_id, in_port, actions = acts)
                        """
                        flow = {}
                        flow['dpid'] = dpid
                        flow['dl_dst'] = BROADCAST
                        flow['in_port'] = in_port
                        flow['dl_type'] = OFI_ETH_TYPE_IP
                        flow['nw_proto'] = OFI_UDP
                        flow['tp_src'] = BOOTP_CLIENT_PORT_PORT_NUMBER
                        flow['nw_dst'] = 0
                        flow['priority'] = OFP_DEFAULT_PRIORITY + 30000
                        flow['idle_timeout'] = 0
                        flow['hard_timeout'] = 0
                        flow['actions'] = actions
                        ofctl_v1_0.mod_flow_entry(dp, flow, dp.ofproto.OFPFC_ADD)
                        dp.send_packet_out(buffer_id, in_port, actions = actions)
                        """
                        return 2
                    LOG.info("dhcp packet detected (%s, %s), (%s), %s -> %s", hex(dpid), in_port,
                             haddr_to_str(dl_src), str(IPAddress(src_ip)), str(IPAddress(dst_ip)))
                    return 0
        return 1

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # print "My packet in handler"
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        contents = EventContents()
        contents.set_dpid(datapath.id)
        contents.set_buff_id(msg.buffer_id)

        dl_dst, dl_src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)
        if _eth_type == ETH_TYPE_LLDP:
            # Don't forward LLDP packets to Janus
            return

        if dl_dst != mac.BROADCAST and is_multicast(dl_dst):
            # drop and install rule to drop
            self._modflow_and_drop_packet(msg, None, dl_dst, OFP_DEFAULT_PRIORITY + 25000, idle_timeout = 360)
            return

        contents.set_in_port(msg.in_port)
        contents.set_dl_dst(haddr_to_str(dl_dst))
        contents.set_dl_src(haddr_to_str(dl_src))
        contents.set_eth_type(_eth_type)

        if _eth_type == 0x806 and dl_dst == mac.BROADCAST:  # ARP, broadcast
            HTYPE, PTYPE, HLEN, PLEN, OPER, SHA, SPA, THA, TPA = struct.unpack_from('!HHbbH6s4s6s4s', buffer(msg.data), 14)
            if self._handle_arp_packets(msg, dl_dst, dl_src, _eth_type,
                                        HTYPE, PTYPE, HLEN, PLEN,
                                        OPER, SHA, SPA, THA, TPA):
                return

            self._drop_packet(msg)

            contents.set_arp_htype(HTYPE)
            contents.set_arp_ptype(PTYPE)
            contents.set_arp_hlen(HLEN)
            contents.set_arp_plen(PLEN)
            contents.set_arp_oper(OPER)

            contents.set_arp_sha(haddr_to_str(SHA))
            contents.set_arp_spa(ipaddr_to_str(SPA))
            contents.set_arp_tha(haddr_to_str(THA))
            contents.set_arp_tpa(ipaddr_to_str(TPA))

            method = 'POST'
            body = {'of_event_id': JANEVENTS.JAN_EV_PACKETIN}
            body.update(contents.getContents())
            body = json.dumps({'event': body})
            header = {"Content-Type": "application/json"}

            url = self.url_prefix
            LOG.info("FORWARDING PACKET TO JANUS: body = %s", body)
            self._forward2Controller(method, url, body, header)
            return

        r1 = self._packet_not_dhcp_request(datapath, datapath.id, int(msg.in_port), int(msg.buffer_id), dl_dst, dl_src, _eth_type, msg.data)
        if r1 == 1:
            (id, pr, eth_t, acts, out_ports,
                idle_timeout, hard_timeout,
                with_src) = self.flow_store.get_flow(
                                           datapath.id, msg.in_port,
                                            haddr_to_str(dl_src), haddr_to_str(dl_dst),
                                            _eth_type)
            if pr is not None and acts is not None:
                actions = ofctl_v1_0.to_actions(datapath, acts)
                if with_src == 0:
                    temp_src = None
                else:
                    temp_src = dl_src
                self._install_modflow(msg, msg.in_port, temp_src, dl_dst, eth_t, actions, pr, idle_timeout, hard_timeout)
                datapath.send_packet_out(int(msg.buffer_id), int(msg.in_port), actions = actions, data = None)
                return
            else:
                ret = self.flow_store.check_if_similar_msg_pending(int(msg.buffer_id), datapath.id, msg.in_port, haddr_to_str(dl_src), haddr_to_str(dl_dst), _eth_type)
                if ret is True:
                    if self.flow_store.add_msg_to_pending(int(msg.buffer_id), datapath.id, msg.in_port, haddr_to_str(dl_src), haddr_to_str(dl_dst), _eth_type) is False:
                        self._drop_packet(msg)
                    return
                else:
                    self.flow_store.add_msg_to_pending(int(msg.buffer_id), datapath.id, msg.in_port, haddr_to_str(dl_src), haddr_to_str(dl_dst), _eth_type)
        elif r1 == 2:
            # means already taken care of
            return


        if _eth_type == 0x800:
#            print msg.data.encode( 'hex' )
#            print repr( msg.data )
#            print buffer( msg.data )

            dummy1, ip_proto, dummy2, src_ip, dst_ip = struct.unpack_from('!BBHLL', buffer(msg.data), 22)
            """
            print '**********************'
            print dummy1, ip_proto, dummy2, src_ip , dst_ip
            print '**********************'
            """
            contents.set_nw_proto(ip_proto)
            contents.set_nw_src(src_ip)
            contents.set_nw_dest(dst_ip)
            if ip_proto == inet.IPPROTO_TCP or ip_proto == inet.IPPROTO_UDP:
                tp_sport, tp_dport = struct.unpack_from('!HH', buffer(msg.data), 34)
                contents.set_tp_sport (tp_sport)
                contents.set_tp_dport (tp_dport)

        method = 'POST'
        body = {'of_event_id': JANEVENTS.JAN_EV_PACKETIN}
        body.update(contents.getContents())
        body = json.dumps({'event': body})
        header = {"Content-Type": "application/json"}

        url = self.url_prefix
        # LOG.info("FORWARDING PACKET TO JANUS: body = %s", body)
        self._forward2Controller(method, url, body, header)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        dpid = msg.datapath_id
        ports = msg.ports

        method = 'PUT'
        body = json.dumps({'event': {'of_event_id': JANEVENTS.JAN_EV_FEATURESREPLY,
                                        'datapath_id': dpid, 'ports': ports.keys()}})
        header = {"Content-Type": "application/json"}

        url = self.url_prefix
        LOG.info("FORWARDING FEATURES REPLY TO JANUS: body = %s", body)
        self._forward2Controller(method, url, body, header)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def dp_handler(self, ev):
        LOG.debug('dp_handler %s %s', ev, ev.enter_leave)
        dp = ev.dp

        if ev.enter_leave:
            self.api_db.load_flows(str(hex(dp.id)), self.flow_store)
            # send any dhcp discovery message up to the controller
            """
            rule = nx_match.ClsRule()
            rule.set_dl_dst(mac.BROADCAST)
            rule.set_dl_type(OFI_ETH_TYPE_IP)
            rule.set_nw_dst(0)
            rule.set_nw_proto(17)
            rule.set_tp_src(BOOTP_CLIENT_PORT_PORT_NUMBER)
            """
            ofproto = dp.ofproto
            ofproto_parser = dp.ofproto_parser
            output = ofproto_parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER, max_len = 200)
            actions = [output]

#            ofctl_v1_0.mod_flow_entry(dp, flow, ofproto.OFPFC_ADD)
            flow = {}
            flow['dl_dst'] = 'ff:ff:ff:ff:ff:ff'
            flow['dl_type'] = OFI_ETH_TYPE_IP
            flow['nw_proto'] = inet.IPPROTO_UDP
            flow['nw_dst'] = "0.0.0.0/32"
            flow['tp_src'] = BOOTP_CLIENT_PORT_PORT_NUMBER
            match = ofctl_v1_0.to_match(dp, flow)
            priority = OFP_DEFAULT_PRIORITY + 12000
            out_port = int(flow.get('out_port', ofproto_v1_0.OFPP_NONE))
            """
            flow_mod = dp.ofproto_parser.OFPFlowMod(
                datapath = dp, match = match, cookie = 0,
                command = ofproto.OFPFC_ADD, idle_timeout = 0,
                hard_timeout = 0, priority = priority,
                flags = 0, actions = actions, out_port = out_port)

            dp.send_msg(flow_mod)
            """

            """
            dp.send_flow_mod(
                rule = rule, cookie = 0, command = ofproto.OFPFC_ADD,
                idle_timeout = 0, hard_timeout = 0, actions = actions,
                priority = OFP_DEFAULT_PRIORITY + 12000)
            """
            # send any arp broadcast message up to the controller
            rule = nx_match.ClsRule()
            rule.set_dl_dst(mac.BROADCAST)
            rule.set_dl_type(OFI_ETH_TYPE_ARP)
            ofproto = dp.ofproto
            ofproto_parser = dp.ofproto_parser
            output = ofproto_parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER, max_len = 100)
            actions = [output]
            dp.send_flow_mod(
                rule = rule, cookie = 0, command = ofproto.OFPFC_ADD,
                idle_timeout = 0, hard_timeout = 0, actions = actions,
                priority = OFP_DEFAULT_PRIORITY + 10000)

            # drop all other broadcast messages
            """
            rule = nx_match.ClsRule()
            rule.set_dl_dst(mac.BROADCAST)
            ofproto = dp.ofproto
            ofproto_parser = dp.ofproto_parser
            actions = []
            dp.send_flow_mod(
                rule = rule, cookie = 0, command = ofproto.OFPFC_ADD,
                idle_timeout = 0, hard_timeout = 0, actions = actions,
                priority = OFP_DEFAULT_PRIORITY + 9000)
            """

        # inform janus of the dp event

        dpid = ev.dp.id
        method = 'PUT'
        body = json.dumps({'event': {'of_event_id': JANEVENTS.JAN_EV_DP_EVENT,
                                        'datapath_id': dpid, 'enter_leave': ev.enter_leave}})
        header = {"Content-Type": "application/json"}

        url = self.url_prefix
        LOG.info("FORWARDING DP EVENT TO JANUS: body = %s", body)
        self._forward2Controller(method, url, body, header)

    def _handle_arp_packets(self, msg, dst, src, _eth_type, HTYPE, PTYPE, HLEN, PLEN,
                                        OPER, SHA, SPA, THA, TPA):
        datapath = msg.datapath
        dpid = datapath.id
    # print 'yes. received arp packet.'
        # print 'HTYPE = %d, PTYPE = %d, HLEN = %d, PLEN = %d, OPER = %d, SHA = %s, SPA = %s, THA = %s, TPA = %s' % (
        #        HTYPE, PTYPE, HLEN, PLEN, OPER, mac.haddr_to_str(SHA), mac.ipaddr_to_str(SPA), mac.haddr_to_str(THA), mac.ipaddr_to_str(TPA))
        if OPER != 1:
            self._drop_packet(msg)
            return True
        dst_ip = SPA
        dst_mac = SHA
        src_ip = TPA
        LOG.info("arp packet: src = %s, dst = %s", mac.ipaddr_to_str(SPA), mac.ipaddr_to_str(TPA))

        src_mac = self.mac2port.mac_ip_get(src_ip)
        if src_mac is not None:
            self._drop_packet(msg)
            mydata = ctypes.create_string_buffer(42)
            struct.pack_into('!6s6sHHHbbH6s4s6s4s', mydata, 0, src, src_mac, _eth_type, HTYPE, PTYPE, HLEN, PLEN, 2, src_mac, src_ip, dst_mac, dst_ip)

            out_port = msg.in_port
            LOG.info("handled arp packet: %s, %s, %s, %s requested by %s, %s", dpid, out_port, mac.haddr_to_str(src_mac), mac.ipaddr_to_str(src_ip),
                     mac.haddr_to_str(src), mac.ipaddr_to_str(dst_ip))
            out_port = msg.in_port
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            datapath.send_packet_out(actions = actions, data = mydata)
            return True
        return False

    def _drop_packet(self, msg):
        datapath = msg.datapath
        datapath.send_packet_out(msg.buffer_id, msg.in_port, [])

    def cleaning_loop(self):
        while self.is_active:
            try:
                gevent.sleep(seconds = 15)
#                LOG.info("clearing expired pending msgs")
                expired_list = self.flow_store.clear_expired_pending_msgs()
                if len(expired_list) > 0:
                    LOG.info("clearing expired pending msgs %s", expired_list)
                for (dpid, in_port, id)  in expired_list:
                    try:
                        datapath = self.dpset.get(dpid)
                        datapath.send_packet_out(id, in_port, [])
                    except:
                        pass
            except:
                pass


