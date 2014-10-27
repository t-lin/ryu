#-------------------------------------------------------------------------------
# Copyright 2013 University of Toronto
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
#
# vim: tabstop=4 shiftwidth=4 softtabstop=4

import logging
import struct
import httplib
import json
import gflags
import ctypes
import gevent
import time
import traceback
import pika

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.controller import flow_store
from ryu.controller import api_db
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_str, ipaddr_to_str, is_multicast, ALL_MAC
from ryu.lib.lldp import ETH_TYPE_LLDP, LLDP_MAC_NEAREST_BRIDGE
from janus.network.of_controller.janus_of_consts import JANEVENTS, JANPORTREASONS
from janus.network.of_controller.event_contents import EventContents
from janus.network.of_controller.janus_of_consts import ARP_TIMEOUT, ARP_CLEANING_TIMER, ARP_AUDIT_TIMER
from ryu.controller import admission_ctrl

from dpkt.ntp import BROADCAST
from ryu.ofproto import nx_match, inet
from ryu.lib import mac, ofctl_v1_0
from netaddr import IPAddress

FLAGS = gflags.FLAGS
gflags.DEFINE_string('janus_host', '127.0.0.1', 'Janus host IP address')
gflags.DEFINE_integer('janus_port', '8091', 'Janus admin API port')
gflags.DEFINE_string('rabbit_user', '', 'Rabbit username')
gflags.DEFINE_string('rabbit_password', '', 'Rabbit password')
gflags.DEFINE_string('rabbit_host', '', 'Rabbit host')
gflags.DEFINE_bool('rabbit_enabled', False, 'ryu2janus rabbit feature')
gflags.DEFINE_bool('rest_enabled', True, 'ryu2janus restful feature')
gflags.DEFINE_bool('second_janus', False, 'Second Janus ENABLED')
gflags.DEFINE_string('dpid_file', None, 'dpid file name')
gflags.DEFINE_string('second_janus_host', '127.0.0.1', 'Second Janus host IP address')
gflags.DEFINE_integer('second_janus_port', '8091', 'Second Janus admin API port')

LOG = logging.getLogger('ryu.app.ryu2janus')

OFI_ETH_TYPE_IP = 2048
OFI_ETH_TYPE_ARP = 0x806
OFI_UDP = 17
BOOTP_CLIENT_PORT_PORT_NUMBER = 68
BOOTP_SERVER_PORT_PORT_NUMBER = 67
OFP_DEFAULT_PRIORITY = 0x8000
OFP_MAX_PRIORITY = 0xffff

USER_FLOW_INSTALL_INTERVAL = 5 * 60
PORT_BW_UPDATE_INTERVAL = 20

ALL_PORTS = -1
class Ryu2JanusForwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'flow_store': flow_store.FlowStore,
        'api_db': api_db.API_DB,
        'mac2port': mac_to_port.MacToPortTable,
        'adm_ctrl': admission_ctrl.RateControl,
    }

    def __init__(self, *args, **kwargs):
        super(Ryu2JanusForwarding, self).__init__(*args, **kwargs)
        self.mac2port = kwargs['mac2port']
        self.dpset = kwargs['dpset']
        self.api_db = kwargs.get('api_db', None)
        self.adm_ctrl = kwargs['adm_ctrl']
        self.dp_port2mac = {}

        # Janus address
        self._conn = None
        self.host = FLAGS.janus_host
        self.port = FLAGS.janus_port
        self.url_prefix = '/v1.0/events/0'
        self.second_janus = FLAGS.second_janus
        self.second_host = FLAGS.second_janus_host
        self.second_port = FLAGS.second_janus_port
        self.second_dpids = {}
        if self.second_janus and self.second_host and self.second_port:
            in_file = FLAGS.dpid_file
            if in_file and len(in_file) > 0:
                try:
                    with open(in_file) as in_f:
                        self.second_dpids = json.load(in_f)
                except:
                    self.second_janus = False

        self.rabbit_user = FLAGS.rabbit_user
        self.rabbit_password = FLAGS.rabbit_password
        self.rabbit_host = FLAGS.rabbit_host
        self.rabbit_enabled = FLAGS.rabbit_enabled
        self.rest_enabled = FLAGS.rest_enabled
        if self.rabbit_enabled:
            self.credentials = pika.PlainCredentials(self.rabbit_user, self.rabbit_password)
            self.connection = pika.BlockingConnection(pika.ConnectionParameters(host = self.rabbit_host, credentials = self.credentials))
            self.channel = self.connection.channel()
            self.channel.exchange_declare(exchange = 'ryuRabbitEvents_exchange', type = 'fanout')

        self.flow_store = kwargs['flow_store']
        self.is_active = True
        self.threads = []
        self.threads.append(gevent.spawn_later(0, self.cleaning_loop))

    def close(self):
        self.is_active = False
        # gevent.killall(self.threads)
        gevent.joinall(self.threads)

    def _install_user_flow(self, datapath, in_port, src, dst, eth_type, actions, priority, idle_timeout, hard_timeout, extra_match, cookie = 0):
        # src and dst are in str format
        ofproto = datapath.ofproto
        if LOG.getEffectiveLevel() == logging.DEBUG:
            if len(actions) > 0:
                act = "out to "
                for action in actions:
                    act += str(action.port) + ","
            else:
                act = "drop"
            LOG.debug("installing user flow from port %s, src %s to dst %s, %s, action %s", in_port, src, dst, extra_match, act)
        if actions is None:
            actions = []

        match = {}
        if extra_match is not None:
            match.update(extra_match)
        match['in_port'] = in_port
        if eth_type is not None:
            match['dl_type'] = eth_type
        if dst is not None and dst != ALL_MAC:
            match['dl_dst'] = dst
        if src is not None:
            match['dl_src'] = src

        # install flow
        """
        rule = nx_match.ClsRule()
        if in_port is not None:
            rule.set_in_port(in_port)
        if dst is not None:
            rule.set_dl_dst(dst)
        if src is not None:
            rule.set_dl_src(src)
        if eth_type is not None:
            rule.set_dl_type(eth_type)
        try:
            if extra_match is not None:
                tp_src = extra_match.get('tp_src', None)
                tp_dst = extra_match.get('tp_dst', None)
                nw_src = extra_match.get('nw_src', None)
                nw_dst = extra_match.get('nw_dst', None)
                nw_proto = extra_match.get('nw_proto', None)
                if tp_src is not None:
                    rule.set_tp_src(tp_src)
                if tp_dst is not None:
                    rule.set_tp_dst(tp_dst)
                if nw_src is not None:
                    rule.set_nw_src(mac.ipaddr_to_bin(nw_src))
                if nw_dst is not None:
                    rule.set_nw_dst(mac.ipaddr_to_bin(nw_dst))
                if nw_proto is not None:
                    rule.set_nw_proto(nw_proto)
        except:
            traceback.print_exc()
            return
        """
        m = ofctl_v1_0.to_match(datapath, match)

        flow_mod = datapath.ofproto_parser.OFPFlowMod(
            datapath = datapath, match = m, cookie = cookie,
            command = datapath.ofproto.OFPFC_ADD, idle_timeout = idle_timeout,
            hard_timeout = hard_timeout, priority = priority,
            out_port = ofproto.OFPP_NONE, flags = ofproto.OFPFF_SEND_FLOW_REM, actions = actions)

        datapath.send_msg(flow_mod)

        """
        datapath.send_flow_mod(
            rule = rule, cookie = 0, command = datapath.ofproto.OFPFC_ADD,
            idle_timeout = idle_timeout, hard_timeout = hard_timeout,
            priority = priority,
            buffer_id = 0xffffffff, out_port = ofproto.OFPP_NONE,
            flags = ofproto.OFPFF_SEND_FLOW_REM, actions = actions)
        """

    def _install_modflow(self, msg, in_port, src, dst = None, eth_type = None, actions = None,
                         priority = OFP_DEFAULT_PRIORITY,
                         idle_timeout = 0, hard_timeout = 0, cookie = 0):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        if LOG.getEffectiveLevel() == logging.DEBUG:
            if len(actions) > 0:
                act = "out to "
                for action in actions:
                    act += str(action.port) + ","
            else:
                act = "drop"
            LOG.debug("installing flow from port %s, src %s to dst %s, action %s", in_port, haddr_to_str(src), haddr_to_str(dst), act)
        if actions is None:
            actions = []

        # install flow
        rule = nx_match.ClsRule()
        if in_port is not None:
            rule.set_in_port(in_port)
        if dst is not None and dst != ALL_MAC:
            rule.set_dl_dst(dst)
        if src is not None:
            rule.set_dl_src(src)
        if eth_type is not None:
            rule.set_dl_type(eth_type)

        datapath.send_flow_mod(
            rule = rule, cookie = cookie, command = datapath.ofproto.OFPFC_ADD,
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

    def _forward2Controller(self, dpid, port_no, method, url, body = None, headers = None):

        if self.rabbit_enabled:
              self.insertInRabbit(body)
        host = self.host
        port = self.port
        if self.second_janus and dpid and port_no and dpid in self.second_dpids:
            if port_no in self.second_dpids[dpid]:
                host = self.second_host
                port = self.second_port
            elif port_no == ALL_PORTS:
                self._forward2Controller(dpid, self.second_dpids[dpid][0], method, url, body, headers)

        if self.rest_enabled:
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
            if res.status in (httplib.OK,
                              httplib.CREATED,
                              httplib.ACCEPTED,
                              httplib.NO_CONTENT):
                return res

            raise httplib.HTTPException(
                res, 'code %d reason %s' % (res.status, res.reason),
                res.getheaders(), res.read())

    def insertInRabbit(self, event):
        LOG.info('\n\n....................in RYU2JANUS APP. RYU IS INSERTING INTO RABBIT - FOR JANUS TO CONSUME (NORTHBOUND)....................\n\n')
        d = json.loads(event)
        value = d['event']
        body = json.dumps(value)
        if self.connection.is_closed:
            self.connection = pika.BlockingConnection(pika.ConnectionParameters(host = self.host, credentials = self.credentials))
        if self.channel.is_closed:
            self.channel.open()
        self.channel.basic_publish(exchange = 'ryuRabbitEvents_exchange',
                      routing_key = '',
                      body = body)
        return

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
        self._forward2Controller(msg.datapath.id, port_no, method, url, body, header)

    def _packet_not_dhcp_request(self, dp, dpid, in_port, buffer_id, dl_dst, dl_src, eth_type, data):
        if dl_dst == mac.BROADCAST and eth_type == 0x800:
            dummy1, ip_proto, dummy2, src_ip, dst_ip = struct.unpack_from('!BBHLL', buffer(data), 22)
            if ip_proto == inet.IPPROTO_UDP:
                tp_sport, tp_dport = struct.unpack_from('!HH', buffer(data), 34)
                if tp_sport == 68:
                    actions = self.flow_store.get_dhcp_flow(dpid, in_port, haddr_to_str(dl_src))
                    if False: #actions is not None:
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
                            command = dp.ofproto.OFPFC_ADD, idle_timeout = 140,
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
        ts = time.time()

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

        if self.flow_store.check_if_mac_blocked(datapath.id, msg.in_port, haddr_to_str(dl_src)):
            self._modflow_and_drop_packet(msg, dl_src, None, OFP_MAX_PRIORITY, idle_timeout = 0)
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
            permitted = self.adm_ctrl.check_if_over_rate(datapath.id, msg.in_port, dl_src, ts)
            if not permitted:
                """send warning to janus"""
                contents.set_ac_warn(True)

            body.update(contents.getContents())
            body = json.dumps({'event': body})
            header = {"Content-Type": "application/json"}

            url = self.url_prefix

            LOG.info("FORWARDING PACKET TO JANUS: body = %s", body)
            self._forward2Controller(datapath.id, msg.in_port, method, url, body, header)
            return

        tp_sport = tp_dport = ip_proto = src_ip = dst_ip = None
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
                #LOG.info( "HERE... %d, %d, %s" % (tp_sport, tp_dport, ipaddr_to_str(dst_ip), haddr_to_str(dl_dst)) ) 
                #LOG.info( "HERE... %d, %d, %s" % (tp_sport, tp_dport, haddr_to_str(dl_dst)) ) 
                contents.set_tp_sport (tp_sport)
                contents.set_tp_dport (tp_dport)
                if dl_dst == mac.BROADCAST and \
                    dst_ip == 0xffffffff and ip_proto == inet.IPPROTO_UDP and \
                    tp_sport == 67 and tp_dport == 68:
                    # DHCP broadcast reply (assume entire packet was forwarded)
                    # Parse client MAC from data and replace dl_dst
                    #LOG.info( "msg.data length is... %s" % len(msg.data) ) 
                    #LOG.info("buffer id is... %s" % msg.buffer_id )
                    buffer_id = msg.buffer_id
                    client_mac, = struct.unpack_from('!6s', buffer(msg.data), 70)
                    #LOG.info("\n\n THE CLIENT MAC IS... %s\n\n" % haddr_to_str(client_mac))

                    # Overwrite destination MAC address and send out
                    actions = []
                    actions.append(datapath.ofproto_parser.OFPActionSetDlDst(client_mac))
                    (id, pr, eth_t, acts, out_ports,
                        idle_timeout, hard_timeout,
                        with_src) = self.flow_store.get_flow(
                                                   datapath.id, msg.in_port,
                                                    haddr_to_str(dl_src), haddr_to_str(client_mac),
                                                    _eth_type, nw_proto = ip_proto,
                                                    tp_src = tp_sport,
                                                    tp_dst = tp_dport,
                                                    nw_src = src_ip,
                                                    nw_dst = dst_ip)
                    if pr is not None and acts is not None:
                        actions.extend(ofctl_v1_0.to_actions(datapath, acts))

                        datapath.send_packet_out(buffer_id=buffer_id, in_port=msg.in_port, actions = actions, data = None) #msg.data)
                    else:
                        self._drop_packet(msg)
                    return

        r1 = self._packet_not_dhcp_request(datapath, datapath.id, int(msg.in_port), int(msg.buffer_id), dl_dst, dl_src, _eth_type, msg.data)
        if r1 == 1:
            (id, pr, eth_t, acts, out_ports,
                idle_timeout, hard_timeout,
                with_src) = self.flow_store.get_flow(
                                           datapath.id, msg.in_port,
                                            haddr_to_str(dl_src), haddr_to_str(dl_dst),
                                            _eth_type, nw_proto = ip_proto,
                                            tp_src = tp_sport,
                                            tp_dst = tp_dport,
                                            nw_src = src_ip,
                                            nw_dst = dst_ip)
            if pr is not None and acts is not None:
                actions = ofctl_v1_0.to_actions(datapath, acts)
                if with_src == 0:
                    temp_src = None
                else:
                    temp_src = dl_src
                self._install_modflow(msg, msg.in_port, temp_src, dl_dst, eth_t, actions, pr, idle_timeout, hard_timeout, cookie = id)
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

        permitted = self.adm_ctrl.check_if_over_rate(datapath.id, msg.in_port, dl_src, ts)
        if not permitted:
            """send warning to janus"""
            contents.set_ac_warn(True)

        method = 'POST'
        body = {'of_event_id': JANEVENTS.JAN_EV_PACKETIN}
        body.update(contents.getContents())
        body = json.dumps({'event': body})
        header = {"Content-Type": "application/json"}

        # LOG.info("FORWARDING PACKET TO JANUS: body = %s", body)
        url = self.url_prefix
        self._forward2Controller(datapath.id, msg.in_port, method, url, body, header)

    def block_port (self, datapath, in_port):
        port_mac = self.dp_port2mac[datapath.id][in_port]
        port_block_msg = datapath.ofproto_parser.OFPPortMod(datapath, in_port, port_mac, 1, 1, 0)
        datapath.send_msg(port_block_msg)
        print "switch ", datapath.id , " Port ", in_port, " blocked!!"

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        dpid = msg.datapath_id
        ports = msg.ports

        for port_key in ports.keys():
            dpid_dict = self.dp_port2mac.setdefault(dpid, {})
            dpid_dict[port_key] = ports[port_key].hw_addr

        method = 'PUT'
        body = json.dumps({'event': {'of_event_id': JANEVENTS.JAN_EV_FEATURESREPLY,
                                        'datapath_id': dpid, 'ports': ports.keys()}})
        header = {"Content-Type": "application/json"}

        url = self.url_prefix
        LOG.info("FORWARDING FEATURES REPLY TO JANUS: body = %s", body)
        self._forward2Controller(dpid, ALL_PORTS, method, url, body, header)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def dp_handler(self, ev):
        LOG.debug('dp_handler %s %s', ev, ev.enter_leave)
        dp = ev.dp

        if ev.enter_leave:
            self.api_db.load_flows(str(hex(dp.id)), self.flow_store)
            self._install_user_flows(dp, dp.id)
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
                ofproto.OFPP_CONTROLLER, max_len = 400)
            actions = [output]

#            ofctl_v1_0.mod_flow_entry(dp, flow, ofproto.OFPFC_ADD)
            # send up all dhcp request with broadcast destination
            flow = {}
            flow['dl_dst'] = 'ff:ff:ff:ff:ff:ff'
            flow['dl_type'] = OFI_ETH_TYPE_IP
            flow['nw_proto'] = inet.IPPROTO_UDP
            flow['tp_src'] = BOOTP_CLIENT_PORT_PORT_NUMBER
            flow['tp_dst'] = BOOTP_SERVER_PORT_PORT_NUMBER
            match = ofctl_v1_0.to_match(dp, flow)
            priority = OFP_DEFAULT_PRIORITY + 10
            out_port = int(flow.get('out_port', ofproto_v1_0.OFPP_NONE))

            flow_mod = dp.ofproto_parser.OFPFlowMod(
                datapath = dp, match = match, cookie = 0,
                command = ofproto.OFPFC_ADD, idle_timeout = 0,
                hard_timeout = 0, priority = priority,
                flags = 0, actions = actions, out_port = out_port)

            dp.send_msg(flow_mod)

            # send up all dhcp responses with broadcast destination
            flow = {}
            flow['dl_dst'] = 'ff:ff:ff:ff:ff:ff'
            flow['dl_type'] = OFI_ETH_TYPE_IP
            flow['nw_proto'] = inet.IPPROTO_UDP
            flow['tp_src'] = BOOTP_SERVER_PORT_PORT_NUMBER
            flow['tp_dst'] = BOOTP_CLIENT_PORT_PORT_NUMBER
            match = ofctl_v1_0.to_match(dp, flow)
            priority = OFP_DEFAULT_PRIORITY + 10
            out_port = int(flow.get('out_port', ofproto_v1_0.OFPP_NONE))

            flow_mod = dp.ofproto_parser.OFPFlowMod(
                datapath = dp, match = match, cookie = 0,
                command = ofproto.OFPFC_ADD, idle_timeout = 0,
                hard_timeout = 0, priority = priority,
                flags = 0, actions = actions, out_port = out_port)

            dp.send_msg(flow_mod)

            # send up all arp with broadcast destination
            flow = {}
            flow['dl_dst'] = 'ff:ff:ff:ff:ff:ff'
            flow['dl_type'] = OFI_ETH_TYPE_ARP
            match = ofctl_v1_0.to_match(dp, flow)
            priority = OFP_DEFAULT_PRIORITY + 10
            out_port = int(flow.get('out_port', ofproto_v1_0.OFPP_NONE))

            flow_mod = dp.ofproto_parser.OFPFlowMod(
                datapath = dp, match = match, cookie = 0,
                command = ofproto.OFPFC_ADD, idle_timeout = 0,
                hard_timeout = 0, priority = priority,
                flags = 0, actions = actions, out_port = out_port)

            dp.send_msg(flow_mod)

            # drop all IPv6 unicast
            flow = {}
            flow['dl_dst'] = '33:33:00:00:00:01'
            match = ofctl_v1_0.to_match(dp, flow)
            priority = 100
            out_port = int(flow.get('out_port', ofproto_v1_0.OFPP_NONE))
            actions = []

            flow_mod = dp.ofproto_parser.OFPFlowMod(
                datapath = dp, match = match, cookie = 0,
                command = ofproto.OFPFC_ADD, idle_timeout = 0,
                hard_timeout = 0, priority = priority,
                flags = 0, actions = actions, out_port = out_port)

            dp.send_msg(flow_mod)

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
            """
            dp.send_flow_mod(
                rule = rule, cookie = 0, command = ofproto.OFPFC_ADD,
                idle_timeout = 0, hard_timeout = 0, actions = actions,
                priority = OFP_DEFAULT_PRIORITY + 10000)
            """

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
        self._forward2Controller(dpid, ALL_PORTS, method, url, body, header)

    def _handle_arp_packets(self, msg, dst, src, _eth_type, HTYPE, PTYPE, HLEN, PLEN,
                                        OPER, SHA, SPA, THA, TPA):
        dp = datapath = msg.datapath
        dpid = datapath.id
    # print 'yes. received arp packet.'
        # print 'HTYPE = %d, PTYPE = %d, HLEN = %d, PLEN = %d, OPER = %d, SHA = %s, SPA = %s, THA = %s, TPA = %s' % (
        #        HTYPE, PTYPE, HLEN, PLEN, OPER, mac.haddr_to_str(SHA), mac.ipaddr_to_str(SPA), mac.haddr_to_str(THA), mac.ipaddr_to_str(TPA))
        if OPER != 1:
            self._drop_packet(msg)
            return True
        in_port = msg.in_port
        actions = self.flow_store.get_arp_flow(dpid, in_port, haddr_to_str(src))
        if actions is not None:
            LOG.info("arp packet handled (%s, %s), (%s)", hex(dpid), in_port,
                     haddr_to_str(src))
            flow = {}
            flow['in_port'] = in_port
            flow['dl_src'] = haddr_to_str(src)
            flow['dl_dst'] = 'ff:ff:ff:ff:ff:ff'
            flow['dl_type'] = OFI_ETH_TYPE_ARP
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
            dp.send_packet_out(msg.buffer_id, in_port, actions = acts)
            return True

        dst_ip = SPA
        dst_mac = SHA
        src_ip = TPA
        LOG.info("arp packet: src = %s, dst = %s", mac.ipaddr_to_str(SPA), mac.ipaddr_to_str(TPA))

        (src_mac, src_dpid, src_port) = self.mac2port.mac_ip_get(src_ip)
        if src_mac is not None:
            out_port = msg.in_port
            self._drop_packet(msg)
            if src_dpid is None or src_port is None or src_dpid != dpid or src_port != out_port:
                mydata = ctypes.create_string_buffer(42)
                struct.pack_into('!6s6sHHHbbH6s4s6s4s', mydata, 0, src, src_mac, _eth_type, HTYPE,
                                 PTYPE, HLEN, PLEN, 2, src_mac, src_ip, dst_mac, dst_ip)

                LOG.info("handled arp packet: %s, %s, %s, %s requested by %s, %s", dpid, out_port,
                         mac.haddr_to_str(src_mac), mac.ipaddr_to_str(src_ip),
                         mac.haddr_to_str(src), mac.ipaddr_to_str(dst_ip))
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                datapath.send_packet_out(actions = actions, data = mydata)
            return True
        return False

    def _drop_packet(self, msg):
        datapath = msg.datapath
        datapath.send_packet_out(msg.buffer_id, msg.in_port, [])

    def cleaning_loop(self):
        expire1 = time.time()
        expire2 = expire1
        expire3 = expire1
        expire4 = expire1
        self.waiters = {}
        port_stats = {}
        while self.is_active:
            try:
                gevent.sleep(seconds = 15)
#                LOG.info("clearing expired pending msgs")
                expired_list = []
                expired_list = self.flow_store.clear_expired_pending_msgs()
                if len(expired_list) > 0:
                    LOG.info("clearing expired pending msgs %s", expired_list)
                for (dpid, in_port, id)  in expired_list:
                    try:
                        datapath = self.dpset.get(dpid)
                        datapath.send_packet_out(id, in_port, [])
                    except:
                        pass
                if (time.time() - expire1) > ARP_CLEANING_TIMER:
                    self.mac2port.clear_old_entries_in_ip_mac()
                    expire1 = time.time()
                if (time.time() - expire2) > ARP_AUDIT_TIMER:
                    ip_to_mac_dict = self.mac2port.get_ip_to_mac_dict()
                    expire2 = time.time()
                    if len(ip_to_mac_dict) > 0:
                        method = 'PUT'
                        new_dict = {}
                        for ip, (mac, t, dp, p) in ip_to_mac_dict.iteritems():
                            try:
                                new_dict[ipaddr_to_str(ip)] = haddr_to_str(mac)
                            except:
                                pass
                        if len(new_dict) > 0:
                            body = json.dumps({'event': {'of_event_id': JANEVENTS.JAN_EV_IP_TO_MAC_LIST, 'ip_dict': new_dict}})
                            header = {"Content-Type": "application/json"}

                            url = self.url_prefix
                            self._forward2Controller(None, None, method, url, body, header)

                if (time.time() - expire3) > USER_FLOW_INSTALL_INTERVAL:
                    expire3 = time.time()
                    dps = self.dpset.get_all()
                    for (dpid, dp) in dps:
                        self._install_user_flows(dp, dpid)
                if (time.time() - expire4) > PORT_BW_UPDATE_INTERVAL:
                    old_time = expire4
                    expire4 = time.time()
                    dps = self.dpset.get_all()
                    bw = {}
                    for (dpid, dp) in dps:
                        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
                            t1 = time.time()
                            ports = ofctl_v1_0.get_port_stats(dp, self.waiters)
                            for dpid_h, ports in ports.items():
                                if int(dpid_h, 16) != dpid:
                                    continue
                                for port in ports:
                                    port_stats.setdefault(dpid, {})
                                    (l_time, l_rx_bytes, l_tx_bytes) = port_stats[dpid].setdefault(port['port_no'], (0, 0, 0))
                                    if l_time != 0:
                                        diff_time = (t1 - l_time)
                                        rx_bw = (port['rx_bytes'] - l_rx_bytes) / diff_time
                                        tx_bw = (port['tx_bytes'] - l_tx_bytes) / diff_time
                                        bw.setdefault(dpid, {})
                                        bw[dpid].setdefault(port['port_no'], (rx_bw, tx_bw))
                                    port_stats[dpid][port['port_no']] = (t1, port['rx_bytes'], port['tx_bytes'])
                    if len(bw) > 0:
                        body = json.dumps({'event': {'of_event_id': JANEVENTS.JAN_EV_PORT_BW_UPDATE, 'bw': bw}})
                        header = {"Content-Type": "application/json"}

                        url = self.url_prefix
                        method = 'PUT'
                        self._forward2Controller(None, None, method, url, body, header)

            except:
                traceback.print_exc()
                pass


    def _install_user_flows(self, dp, dpid):
        user_flow_dict = self.flow_store.get_user_flows(dpid)
        LOG.info('dp_handler %s %s user_flows loaded', dpid, len(user_flow_dict))
        for id, (in_port, dest, src, eth_type, pr, acts, out_ports, idle_timeout, hard_timeout, user_id, extra_match) in user_flow_dict.iteritems():
            actions = ofctl_v1_0.to_actions(dp, acts)
            if src == '0' or src is None:
                temp_src = None
            else:
                temp_src = src
            self._install_user_flow(dp, in_port, src, dest, eth_type, actions, pr, idle_timeout, hard_timeout, extra_match, cookie = id)
        return

    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        # print 'stats_reply_handler:', msg.xid
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        if msg.flags & dp.ofproto.OFPSF_REPLY_MORE:
            return
        del self.waiters[dp.id][msg.xid]
        lock.set()

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        self.stats_reply_handler(ev)
