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

import logging
import ctypes
import struct
import datetime
import calendar
import gflags
import traceback

import json
from webob import Response

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import flow_store
from ryu.controller import api_db
from ryu.controller import mac_to_port
from ryu.ofproto import ofproto_v1_0
from ryu.lib import ofctl_v1_0
from ryu.lib.mac import haddr_to_bin, ipaddr_to_bin
from ryu.app.wsgi import ControllerBase, WSGIApplication
from janus.network.of_controller import event_contents


LOG = logging.getLogger('ryu.app.ofctl_rest')

# REST API
#
# # Retrieve the switch stats
#
# get the list of all switches
# GET /stats/switches
#
# get the desc stats of the switch
# GET /stats/desc/<dpid>
#
# get flows stats of the switch
# GET /stats/flow/<dpid>
#
# get ports stats of the switch
# GET /stats/port/<dpid>
#
# # Update the switch stats
#
# add a flow entry
# POST /stats/flowentry
#
# delete flows of the switch
# DELETE /stats/flowentry/clear/<dpid>
#


class StatsController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(StatsController, self).__init__(req, link, data, **config)
        self.dpset = data['dpset']
        self.waiters = data['waiters']
        self.flow_store = data.get('flow_store', None)
        self.mac2port = data.get('mac2port', None)
        self.api_db = data.get('api_db', None)
        assert self.mac2port is not None
        assert self.flow_store is not None
        assert self.api_db is not None

    def get_dpids(self, req, **_kwargs):
        dps = self.dpset.dps.keys()
        body = json.dumps([(a, hex(int(a))) for a in dps])
        return (Response(content_type = 'application/json', body = body))

    def get_desc_stats(self, req, dpid, **_kwargs):
        dp = self.dpset.get(int(dpid))
        if dp is None:
            return Response(status = 404)

        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            desc = ofctl_v1_0.get_desc_stats(dp, self.waiters)
        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status = 501)

        body = json.dumps(desc)
        return (Response(content_type = 'application/json', body = body))

    def get_flow_stats(self, req, dpid, **_kwargs):
        dp = self.dpset.get(int(dpid))
        if dp is None:
            return Response(status = 404)

        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            flows = ofctl_v1_0.get_flow_stats(dp, self.waiters)
        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status = 501)

        body = json.dumps(flows)
        return (Response(content_type = 'application/json', body = body))

    def get_port_stats(self, req, dpid, **_kwargs):
        dp = self.dpset.get(int(dpid))
        if dp is None:
            return Response(status = 404)

        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            ports = ofctl_v1_0.get_port_stats(dp, self.waiters)
        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status = 501)

        body = json.dumps(ports)
        return (Response(content_type = 'application/json', body = body))

    def mac_ip_del_list(self, req, **_kwargs):
        try:
            body = eval(req.body)
        except SyntaxError:
            LOG.debug('invalid syntax in mac_ip_del_list %s', req.body)
            return Response(status = 400)

        ip_list = body.get('mac_ip_list', [])
        for (mac, ip) in ip_list:
            try:
                self.mac2port.mac_ip_del(haddr_to_bin(mac), ipaddr_to_bin(ip))
            except:
                pass

        return Response(status = 200)

    def mac_ip_add(self, req, **_kwargs):
        try:
            body = eval(req.body)
        except SyntaxError:
            LOG.debug('invalid syntax %s', req.body)
            return Response(status = 400)
        mac = body.get('mac', None)
        dpid = body.get('dpid', None)
        ip = body.get('ip', None)
        port_no = body.get('port_no', None)
        try:
            self.mac2port.mac_ip_add(mac = haddr_to_bin(mac), ip = ipaddr_to_bin(ip))
        except ValueError:
            print 'Invalid ip address format. Check the ip you are registering: %s' % ip
            return Response(status = 500)
        except:
            return Response(status = 500)
        return Response(status = 200)

    def mac_ip_del(self, req, dpid, port_no, mac, **_kwargs):
        try:
            LOG.info('mac_ip_del requested %s, %s, %s, %s', dpid, port_no, mac, req.body)
            body = json.loads(req.body)
        except:
            traceback.print_exc()
            LOG.debug('invalid syntax %s', req.body)
            return Response(status = 400)
        ip = body.get('ip', None)
        if ip == '0.0.0.0':
            ip = None
        dpid_list = body.get('dpid_list', [])
        for id in dpid_list:
            dp = self.dpset.get(int(id))
            cmd = dp.ofproto.OFPFC_DELETE
            flow = {}
            flow['match'] = {}
            flow['match']['dl_src'] = mac
            ofctl_v1_0.mod_flow_entry(dp, flow, cmd)
            flow = {}
            flow['match'] = {}
            flow['match']['dl_dst'] = mac
            ofctl_v1_0.mod_flow_entry(dp, flow, cmd)

        ip = None
        try:
            self.flow_store.del_dhcp_flow(int(dpid), int(port_no), mac)
        except:
            pass
        try:
            self.flow_store.del_mac_flows(int(dpid), int(port_no), mac)
        except:
            pass
        ip_bin = None
        try:
            if ip is not None:
                ip_bin = ipaddr_to_bin(ip)
        except:
            ip_bin = None

        try:
            self.mac2port.mac_ip_del(mac = haddr_to_bin(mac), ip = ip_bin)
        except ValueError:
            print 'Invalid ip address format. Check the ip you are registering: %s' % ip
            return Response(status = 500)
        except:
            return Response(status = 500)
        return Response(status = 200)

    def list_flow_store(self, req, dpid = None, **_kwargs):
        dp = None
        try:
            dp = int(dpid, 16)
        except:
            dp = None
            pass
        flows = self.flow_store.get_all_flows(dp)

        body = json.dumps(flows)
        return (Response(content_type = 'application/json', body = body))

    def mod_flow_entry(self, req, cmd, **_kwargs):
        try:
            flow = eval(req.body)
        except:
            LOG.debug('invalid syntax %s', req.body)
            return Response(status = 400)

        dpid = flow.get('dpid')
        dp = self.dpset.get(int(dpid))
        if dp is None:
            return Response(status = 404)
        id = 0
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            if cmd == 'add':
                cmd = dp.ofproto.OFPFC_ADD
                id = self.flow_store.add_flow_dict(flow, self.api_db)
            elif cmd == 'modify':
                cmd = dp.ofproto.OFPFC_MODIFY
            elif cmd == 'delete':
                self.flow_store.del_flow_dict(flow, self.api_db)
                cmd = dp.ofproto.OFPFC_DELETE
                print "dpid %s, %s, flow in delete is %s" % (dpid, hex(dpid), flow)
            else:
                return Response(status = 404)

            ofctl_v1_0.mod_flow_entry(dp, flow, cmd)
        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status = 501)

        return Response(status = 200, body = str(id))

    def get_user_flow(self, req, user_id, dpid, id = None, **_kwargs):
        user_flow_dict = self.flow_store.get_user_flows(int(dpid, 16), user_id, id)
        return Response(status = 200, body = json.dumps(user_flow_dict))

    def del_user_flow(self, req, user_id, dpid = None, id = None, **_kwargs):
        id_list = []
        if id is not None:
            id_list.append((dpid, id))
        try:
            if req.body is not None and len(req.body) > 0:
                list = eval(req.body)
                id_list.extend(list)
        except:
            LOG.debug('invalid syntax in del_user_flow %s', req.body)
            return Response(status = 400)


        try:
            for (dp_id, i) in id_list:
                (d_id, pr, in_port, src, dst, eth_type, extra_match) = self.flow_store.del_user_flow(self.api_db, dp_id, user_id, int(i))
                if d_id is not None:
                    flow = {}
                    flow['dpid'] = d_id
                    dp = self.dpset.get(int(d_id))
                    flow['in_port'] = in_port
                    flow['priority'] = pr
                    flow['match'] = {}
                    flow['match']['in_port'] = in_port
                    flow['match']['dl_src'] = src
                    flow['match']['dl_dst'] = dst
                    flow['match']['eth_type'] = eth_type
                    flow['match'].update(extra_match)
                    ofctl_v1_0.mod_flow_entry(dp, flow, dp.ofproto.OFPFC_DELETE)
        except:
            traceback.print_exc()
            return Response(status = 500)

        return Response(status = 200)

    def delete_flow_entry(self, req, dpid, **_kwargs):
        dp = self.dpset.get(int(dpid))
        if dp is None:
            return Response(status = 404)

        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            ofctl_v1_0.delete_flow_entry(dp)
        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status = 501)

        return Response(status = 200)

class PacketController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(PacketController, self).__init__(req, link, data, **config)
        self.dpset = data.get('dpset', None)
        self.mac2port = data.get('mac2port', None)
        self.flow_store = data.get('flow_store', None)
        assert self.dpset is not None
        assert self.mac2port is not None

    def output_packet(self, req, dpid, buffer_id, in_port):
        dpid = int(dpid)
        buffer_id = int(buffer_id)
        in_port = int(in_port)

        try:
            # out_port_list = eval(req.body)
            output_dict = eval(req.body)
            out_port_list = output_dict.get('out_port_list')
            mydata = output_dict.get('data')
            acts = output_dict.get('actions', None)
            assert type(output_dict) is dict
            # TODO: put assert for mydata, but sometimes data might be Null
            # assert type(mydata) is str
            assert type(out_port_list) is list
        except SyntaxError:
            LOG.debug('invalid syntax %s', req.body)
            return Response(status = 400)

        datapath = self.dpset.get(dpid)
        assert datapath is not None
        ofproto = datapath.ofproto

        if acts is not None:
            actions = ofctl_v1_0.to_actions(datapath, acts)
        else:
            actions = []
            for out_port in out_port_list:
                actions.append(datapath.ofproto_parser.OFPActionOutput(int(out_port)))

        if mydata is not None:
            mydata = eval(mydata)
            src = mydata.get(event_contents.DL_SRC)
            dst = mydata.get(event_contents.DL_DST)
            _eth_type = mydata.get(event_contents.ETH_TYPE)
            HTYPE = mydata.get(event_contents.ARP_HTYPE)
            PTYPE = mydata.get(event_contents.ARP_PTYPE)
            HLEN = mydata.get(event_contents.ARP_HLEN)
            PLEN = mydata.get(event_contents.ARP_PLEN)
            OPER = mydata.get(event_contents.ARP_OPER)
            SPA = mydata.get(event_contents.ARP_SPA)
            SHA = mydata.get(event_contents.ARP_SHA)
            TPA = mydata.get(event_contents.ARP_TPA)
            THA = mydata.get(event_contents.ARP_THA)
            self.mac2port.mac_ip_add(mac = haddr_to_bin(SHA), ip = ipaddr_to_bin(SPA))
            mybuffer = ctypes.create_string_buffer(42)

            struct.pack_into('!6s6sHHHbbH6s4s6s4s',
                             mybuffer, 0, haddr_to_bin(dst), haddr_to_bin(src),
                             _eth_type, HTYPE, PTYPE, HLEN, PLEN, OPER,
                             haddr_to_bin(SHA), ipaddr_to_bin(SPA),
                             haddr_to_bin(THA), ipaddr_to_bin(TPA))
            datapath.send_packet_out(actions = actions, data = mybuffer)
        else:
            datapath.send_packet_out(int(buffer_id), int(in_port), actions = actions, data = None)
            buffer_ids = self.flow_store.get_similar_pending_msgs(dpid, int(in_port), int(buffer_id))
            for id in buffer_ids:
                if id == int(buffer_id):
                    continue
                datapath.send_packet_out(int(id), int(in_port), actions = actions, data = None)

            self.flow_store.remove_msg_from_pending(dpid, int(in_port), int(buffer_id))

        return Response(status = 200)

    def drop_packet(self, req, dpid, buffer_id, in_port):
        dpid = int(dpid)
        buffer_id = int(buffer_id)
        in_port = int(in_port)

        datapath = self.dpset.get(dpid)
        assert datapath is not None
        LOG.info('\nthe packet is going to be dropped. dpid=%s, in_port=%s\n', dpid, in_port)
        datapath.send_packet_out(buffer_id, in_port, [])
        buffer_ids = self.flow_store.get_similar_pending_msgs(dpid, int(in_port), int(buffer_id))
        for id in buffer_ids:
            if id == int(buffer_id):
                continue
            datapath.send_packet_out(int(id), int(in_port), actions = [])

        self.flow_store.remove_msg_from_pending(dpid, int(in_port), int(buffer_id))
        return Response(status = 200)

class RestStatsApi(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication,
        'flow_store': flow_store.FlowStore,
        'mac2port': mac_to_port.MacToPortTable,
        'api_db': api_db.API_DB
    }

    def __init__(self, *args, **kwargs):
        super(RestStatsApi, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        self.flow_store = kwargs['flow_store']
        self.mac2port = kwargs['mac2port']
        self.api_db = kwargs['api_db']
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters
        self.data['flow_store'] = self.flow_store
        self.data['mac2port'] = self.mac2port
        self.data['api_db'] = self.api_db
        mapper = wsgi.mapper

        wsgi.registory['StatsController'] = self.data
        path = '/stats'
        uri = path + '/switches'
        mapper.connect('stats', uri,
                       controller = StatsController, action = 'get_dpids',
                       conditions = dict(method = ['GET']))

        uri = path + '/desc/{dpid}'
        mapper.connect('stats', uri,
                       controller = StatsController, action = 'get_desc_stats',
                       conditions = dict(method = ['GET']))

        uri = path + '/flow/{dpid}'
        mapper.connect('stats', uri,
                       controller = StatsController, action = 'get_flow_stats',
                       conditions = dict(method = ['GET']))

        uri = path + '/port/{dpid}'
        mapper.connect('stats', uri,
                       controller = StatsController, action = 'get_port_stats',
                       conditions = dict(method = ['GET']))

        uri = path + '/user_flow/{user_id}/{dpid}/{id}'
        mapper.connect('stats', uri,
                       controller = StatsController, action = 'get_user_flow',
                       conditions = dict(method = ['GET']))

        uri = path + '/user_flow/{user_id}/{dpid}'
        mapper.connect('stats', uri,
                       controller = StatsController, action = 'get_user_flow',
                       conditions = dict(method = ['GET']))

        uri = path + '/del_user_flow/{user_id}/{dpid}/{id}'
        mapper.connect('stats', uri,
                       controller = StatsController, action = 'del_user_flow',
                       conditions = dict(method = ['POST']))

        uri = path + '/del_user_flow/{user_id}'
        mapper.connect('stats', uri,
                       controller = StatsController, action = 'del_user_flow',
                       conditions = dict(method = ['POST']))

        uri = path + '/flowentry/{cmd}'
        mapper.connect('stats', uri,
                       controller = StatsController, action = 'mod_flow_entry',
                       conditions = dict(method = ['POST']))


        uri = path + '/flowentry/clear/{dpid}'
        mapper.connect('stats', uri,
                       controller = StatsController, action = 'delete_flow_entry',
                       conditions = dict(method = ['DELETE']))

        uri = path + '/flowentry/store/{dpid}'
        mapper.connect('stats', uri,
                       controller = StatsController, action = 'list_flow_store',
                       conditions = dict(method = ['GET']))

        uri = path + '/flowentry/store'
        mapper.connect('stats', uri,
                       controller = StatsController, action = 'list_flow_store',
                       conditions = dict(method = ['GET']))

        uri = path + '/mac_ip'
        mapper.connect('stats', uri,
                       controller = StatsController, action = 'mac_ip_add',
                       conditions = dict(method = ['POST']))

        mapper.connect('stats', uri + '/del_list',
                       controller = StatsController, action = 'mac_ip_del_list',
                       conditions = dict(method = ['POST']))

        mapper.connect('stats', uri + '/del/{dpid}_{port_no}_{mac}',
                       controller = StatsController, action = 'mac_ip_del',
                       conditions = dict(method = ['POST']))


        # For Janus -> Ryu APIs
        wsgi.registory['PacketController'] = self.data
        uri = '/v1.0/packetAction'
        mapper.connect('pktCtl', uri + '/{dpid}/output/{buffer_id}_{in_port}',
                       controller = PacketController, action = 'output_packet',
                       conditions = dict(method = ['PUT']))

        mapper.connect('pktCtl', uri + '/{dpid}/drop/{buffer_id}_{in_port}',
                       controller = PacketController, action = 'drop_packet',
                       conditions = dict(method = ['DELETE']))

    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)
#        print 'stats_reply_handler:', msgs

        if msg.flags & dp.ofproto.OFPSF_REPLY_MORE:
            return
        del self.waiters[dp.id][msg.xid]
        lock.set()

    @set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER)
    def desc_stats_reply_handler(self, ev):
        self.stats_reply_handler(ev)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        self.stats_reply_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        self.stats_reply_handler(ev)
