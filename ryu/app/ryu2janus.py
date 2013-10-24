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

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_str, ipaddr_to_str, is_multicast
from ryu.lib.lldp import ETH_TYPE_LLDP, LLDP_MAC_NEAREST_BRIDGE
from janus.network.of_controller.janus_of_consts import JANEVENTS, JANPORTREASONS
from janus.network.of_controller.event_contents import EventContents
from dpkt.ntp import BROADCAST
from ryu.ofproto import nx_match, inet
from ryu.lib import mac

FLAGS = gflags.FLAGS
gflags.DEFINE_string( 'janus_host', '127.0.0.1', 'Janus host IP address' )
gflags.DEFINE_integer( 'janus_port', '8091', 'Janus admin API port' )

LOG = logging.getLogger( 'ryu.app.ryu2janus' )

class Ryu2JanusForwarding( app_manager.RyuApp ):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__( self, *args, **kwargs ):
        super( Ryu2JanusForwarding, self ).__init__( *args, **kwargs )
        self.mac_to_port = {}

        # Janus address
        self._conn = None
        self.host = FLAGS.janus_host
        self.port = FLAGS.janus_port
        self.url_prefix = '/v1.0/events/0'

    def _install_modflow( self, msg, in_port, src, dst = None, actions = None ):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        if LOG.getEffectiveLevel() == logging.DEBUG:
            if len( actions ) > 0:
                act = "out to "
                for action in actions:
                    act += str( action.port ) + ","
            else:
                act = "drop"
            LOG.debug( "installing flow from port %s, src %s to dst %s, action %s", msg.in_port, haddr_to_str( src ), haddr_to_str( dst ), act )
        if actions is None:
            actions = []

        # install flow
        rule = nx_match.ClsRule()
        if in_port is not None:
            rule.set_in_port( in_port )
        if dst is not None:
            rule.set_dl_dst( dst )
        if src is not None:
            rule.set_dl_src( src )
        datapath.send_flow_mod( 
            rule = rule, cookie = 0, command = datapath.ofproto.OFPFC_ADD,
            idle_timeout = 0, hard_timeout = 0,
            priority = ofproto.OFP_DEFAULT_PRIORITY,
            buffer_id = 0xffffffff, out_port = ofproto.OFPP_NONE,
            flags = ofproto.OFPFF_SEND_FLOW_REM, actions = actions )

    def _modflow_and_drop_packet( self, msg, in_port, src, dst ):
        LOG.info( "installing flow for dropping packet" )
        datapath = msg.datapath
        in_port = msg.in_port

        self._install_modflow( msg, in_port, src, dst, [] )
        datapath.send_packet_out( msg.buffer_id, in_port, [] )

    def _forward2Controller( self, method, url, body = None, headers = None ):

        try:
            self._conn.request( method, url, body, headers )
            res = conn.getresponse()
        except:
            try:
                self._conn = httplib.HTTPConnection( self.host, self.port )
                self._conn.request( method, url, body, headers )
                res = self._conn.getresponse()
            except:
                LOG.warning( "Failed to Send to Janus: body = %s", body )
                return
            pass
        print "\n"
        if res.status in ( httplib.OK,
                          httplib.CREATED,
                          httplib.ACCEPTED,
                          httplib.NO_CONTENT ):
            return res

        raise httplib.HTTPException( 
            res, 'code %d reason %s' % ( res.status, res.reason ),
            res.getheaders(), res.read() )


    @set_ev_cls( ofp_event.EventOFPPortStatus, MAIN_DISPATCHER )
    def _port_status_handler( self, ev ):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            LOG.info( "port added %s", port_no )
            reason_id = JANPORTREASONS.JAN_PORT_ADD
            method = 'POST'
        elif reason == ofproto.OFPPR_DELETE:
            LOG.info( "port deleted %s", port_no )
            reason_id = JANPORTREASONS.JAN_PORT_DELETE
            method = 'PUT'  # 'DELETE' doesn't support a body in the request
        elif reason == ofproto.OFPPR_MODIFY:
            LOG.info( "port modified %s", port_no )
            reason_id = JANPORTREASONS.JAN_PORT_MODIFY
            method = 'PUT'
        else:
            LOG.info( "Illegal port state %s %s", port_no, reason )
            LOG.info( "UNKNOWN PORT STATUS REASON" )
            raise

        # TO DO: Switch to using EventContents class
        body = json.dumps( {'event': {'of_event_id': JANEVENTS.JAN_EV_PORTSTATUS,
                                        'datapath_id': msg.datapath.id,
                                        'reason': reason_id, 'port': port_no}} )
        header = {"Content-Type": "application/json"}

        url = self.url_prefix
        LOG.info( "FORWARDING PORT STATUS TO JANUS: body = %s", body )
        self._forward2Controller( method, url, body, header )


    @set_ev_cls( ofp_event.EventOFPPacketIn, MAIN_DISPATCHER )
    def _packet_in_handler( self, ev ):
        # print "My packet in handler"
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        contents = EventContents()
        contents.set_dpid( datapath.id )
        contents.set_buff_id( msg.buffer_id )

        dl_dst, dl_src, _eth_type = struct.unpack_from( '!6s6sH', buffer( msg.data ), 0 )
        if _eth_type == ETH_TYPE_LLDP:
            # Don't forward LLDP packets to Janus
            return

        if dl_dst != mac.BROADCAST and is_multicast( dl_dst ):
            # drop and install rule to drop
            self._modflow_and_drop_packet( msg, None, None, dl_dst )
            return

        contents.set_in_port( msg.in_port )
        contents.set_dl_dst( haddr_to_str( dl_dst ) )
        contents.set_dl_src( haddr_to_str( dl_src ) )
        contents.set_eth_type( _eth_type )

        if _eth_type == 0x806:  # ARP
            HTYPE, PTYPE, HLEN, PLEN, OPER, SHA, SPA, THA, TPA = struct.unpack_from( '!HHbbH6s4s6s4s', buffer( msg.data ), 14 )
            contents.set_arp_htype( HTYPE )
            contents.set_arp_ptype( PTYPE )
            contents.set_arp_hlen( HLEN )
            contents.set_arp_plen( PLEN )
            contents.set_arp_oper( OPER )

            contents.set_arp_sha( haddr_to_str( SHA ) )
            contents.set_arp_spa( ipaddr_to_str( SPA ) )
            contents.set_arp_tha( haddr_to_str( THA ) )
            contents.set_arp_tpa( ipaddr_to_str( TPA ) )

        if _eth_type == 0x800:
#            print msg.data.encode( 'hex' )
#            print repr( msg.data )
#            print buffer( msg.data )

            dummy1, ip_proto, dummy2, src_ip, dst_ip = struct.unpack_from( '!BBHLL', buffer( msg.data ), 22 )
            print '**********************'
            print dummy1, ip_proto, dummy2, src_ip , dst_ip
            print '**********************'
            contents.set_nw_proto( ip_proto )
            contents.set_nw_src( src_ip )
            contents.set_nw_dest( dst_ip )
            if ip_proto == inet.IPPROTO_TCP or ip_proto == inet.IPPROTO_UDP:
                tp_sport, tp_dport = struct.unpack_from( '!HH', buffer( msg.data ), 34 )
                contents.set_tp_sport ( tp_sport )
                contents.set_tp_dport ( tp_dport )

        method = 'POST'
        body = {'of_event_id': JANEVENTS.JAN_EV_PACKETIN}
        body.update( contents.getContents() )
        body = json.dumps( {'event': body} )
        header = {"Content-Type": "application/json"}

        url = self.url_prefix
        LOG.info( "FORWARDING PACKET TO JANUS: body = %s", body )
        self._forward2Controller( method, url, body, header )

    @set_ev_cls( ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER )
    def switch_features_handler( self, ev ):
        msg = ev.msg
        dpid = msg.datapath_id
        ports = msg.ports

        method = 'PUT'
        body = json.dumps( {'event': {'of_event_id': JANEVENTS.JAN_EV_FEATURESREPLY,
                                        'datapath_id': dpid, 'ports': ports.keys()}} )
        header = {"Content-Type": "application/json"}

        url = self.url_prefix
        LOG.info( "FORWARDING FEATURES REPLY TO JANUS: body = %s", body )
        self._forward2Controller( method, url, body, header )

