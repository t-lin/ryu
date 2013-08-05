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

import httplib
import logging
import struct
import time

import json
from webob import Response

from ryu.base import app_manager
from ryu.controller import network
from ryu.exception import NetworkNotFound, NetworkAlreadyExist
from ryu.exception import PortNotFound, PortAlreadyExist
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller import link_set
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib import ofctl_v1_0
from ryu.lib.dpid import dpid_to_str
from ryu.lib import dpid as lib_dpid
from ryu.lib.mac import haddr_to_str
from ryu.app.wsgi import ControllerBase, WSGIApplication


LOG = logging.getLogger('ryu.app.rest_savi')

## TODO:XXX
## define db interface and store those information into db

# REST API

# get the list of networks
# GET /v1.0/networks/
#
# register a new network.
# Fail if the network is already registered.
# POST /v1.0/networks/{network-id}
#
# update a new network.
# Success as nop even if the network is already registered.
#
# PUT /v1.0/networks/{network-id}
#
# remove a network
# DELETE /v1.0/networks/{network-id}
#
# get the list of sets of dpid and port
# GET /v1.0/networks/{network-id}/
#
# register a new set of dpid and port
# Fail if the port is already registered.
# POST /v1.0/networks/{network-id}/{dpid}_{port-id}
#
# update a new set of dpid and port
# Success as nop even if same port already registered
# PUT /v1.0/networks/{network-id}/{dpid}_{port-id}
#
# remove a set of dpid and port
# DELETE /v1.0/networks/{network-id}/{dpid}_{port-id}

# We store networks and ports like the following:
#
# {network_id: [(dpid, port), ...
# {3: [(3,4), (4,7)], 5: [(3,6)], 1: [(5,6), (4,5), (4, 10)]}
#


# REST API
#
## Retrieve the switch stats
#
# get the list of all switches
# GET /v1.0/stats/switches
#
# get the desc stats of the switch
# GET /v1.0/stats/desc/<dpid>
#
# get flows stats of the switch
# GET /v1.0/stats/flow/<dpid>
#
# get ports stats of the switch
# GET /v1.0/stats/port/<dpid>
#
# get devices stats
# GET /v1.0/stats/devices
#
## Update the switch stats
#
# add a flow entry
# POST /v1.0/stats/flowentry
#
# delete flows of the switch
# DELETE /v1.0/stats/flowentry/clear/<dpid>
#
## Retrieve topology
#
# get all the links
# GET /v1.0/topology/links
#
# get the links connected <dpid>
# GET /v1.0/topology/switch/dpid>/links
#

class NetworkController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(NetworkController, self).__init__(req, link, data, **config)
        self.nw = data

    def create(self, req, network_id, **_kwargs):
        try:
            self.nw.create_network(network_id)
        except NetworkAlreadyExist:
            return Response(status=409)
        else:
            return Response(status=200)

    def update(self, req, network_id, **_kwargs):
        self.nw.update_network(network_id)
        return Response(status=200)

    def lists(self, req, **_kwargs):
        body = json.dumps(self.nw.list_networks())
        return Response(content_type='application/json', body=body)

    def delete(self, req, network_id, **_kwargs):
        try:
            self.nw.remove_network(network_id)
        except NetworkNotFound:
            return Response(status=404)

        return Response(status=200)


class PortController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(PortController, self).__init__(req, link, data, **config)
        self.nw = data

    def create(self, req, network_id, dpid, port_id, **_kwargs):
        try:
            self.nw.create_port(network_id, int(dpid, 16), int(port_id))
        except NetworkNotFound:
            return Response(status=404)
        except PortAlreadyExist:
            return Response(status=409)

        return Response(status=200)

    def update(self, req, network_id, dpid, port_id, **_kwargs):
        try:
            self.nw.update_port(network_id, int(dpid, 16), int(port_id))
        except NetworkNotFound:
            return Response(status=404)

        return Response(status=200)

    def lists(self, req, network_id, **_kwargs):
        try:
            body = json.dumps(self.nw.list_ports(network_id))
        except NetworkNotFound:
            return Response(status=404)

        return Response(content_type='application/json', body=body)

    def delete(self, req, network_id, dpid, port_id, **_kwargs):
        try:
            self.nw.remove_port(network_id, int(dpid, 16), int(port_id))
        except (NetworkNotFound, PortNotFound):
            return Response(status=404)

        return Response(status=200)



class StatsController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(StatsController, self).__init__(req, link, data, **config)
        self.dpset = data['dpset']
        self.waiters = data['waiters']
        self.devices = data['device']

    def get_dpids(self, req, **_kwargs):
        dps = self.dpset.dps.keys()
	dpstr = []
	for dp in dps:
	    dpstr.append(dpid_to_str(dp))
        body = json.dumps(dpstr)
        return (Response(content_type='application/json', body=body))

    def get_devices(self, req, **_kwargs):
        body = json.dumps(self.devices)
        return (Response(content_type='application/json', body=body))

    def get_features(self, req, dpid, **_kwargs):
        dp = self.dpset.get(int(dpid,16))
        if dp is None:
            return Response(status=404)

        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            features = ofctl_v1_0.get_features(dp, self.waiters)
        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        body = json.dumps(features)
        return (Response(content_type='application/json', body=body))

    def get_desc_stats(self, req, dpid, **_kwargs):
        dp = self.dpset.get(int(dpid,16))
        if dp is None:
            return Response(status=404)

        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            desc = ofctl_v1_0.get_desc_stats(dp, self.waiters)
        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        body = json.dumps(desc)
        return (Response(content_type='application/json', body=body))

    def get_flow_stats(self, req, dpid, **_kwargs):
        dp = self.dpset.get(int(dpid,16))
        if dp is None:
            return Response(status=404)

        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            flows = ofctl_v1_0.get_flow_stats(dp, self.waiters)
        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        body = json.dumps(flows)
        return (Response(content_type='application/json', body=body))

    def get_port_stats(self, req, dpid, **_kwargs):
        dp = self.dpset.get(int(dpid,16))
        if dp is None:
            return Response(status=404)

        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            ports = ofctl_v1_0.get_port_stats(dp, self.waiters)
        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        body = json.dumps(ports)
        return (Response(content_type='application/json', body=body))

    def push_flow_entry(self, req, **_kwargs):
        try:
            flow = eval(req.body)
        except SyntaxError:
            LOG.debug('invalid syntax %s', req.body)
            return Response(status=400)

        dpid = flow.get('dpid')
        dp = self.dpset.get(int(dpid))
        if dp is None:
            return Response(status=404)

        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            ofctl_v1_0.push_flow_entry(dp, flow)
        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        return Response(status=200)

    def delete_flow_entry(self, req, dpid, **_kwargs):
        dp = self.dpset.get(int(dpid,16))
        if dp is None:
            return Response(status=404)

        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            ofctl_v1_0.delete_flow_entry(dp)
        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        return Response(status=200)

class DiscoveryController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(DiscoveryController, self).__init__(req, link, data, **config)
        self.dpset = data['dpset']
        self.link_set = data['link_set']

    @staticmethod
    def _format_link(link, timestamp, now):
        return {
            'timestamp': now - timestamp,
            'dp1': lib_dpid.dpid_to_str(link.src.dpid),
            'port1': link.src.port_no,
            'dp2': lib_dpid.dpid_to_str(link.dst.dpid),
            'port2': link.dst.port_no,
        }

    def _format_response(self, iteritems):
        now = time.time()
        response = {
            'identifier': 'name',
            'items': [self._format_link(link, ts, now)
                      for link, ts in iteritems],
        }
        return json.dumps(response)

    def get_links(self, req, **_kwargs):
	body = self._format_response(self.link_set.get_items())
        return (Response(content_type='application/json', body=body))

    def get_switch_links(self, req, dpid):
        dp = self.dpset.get(int(dpid,16))
        if dp is None:
            body = 'dpid %s is not found\n' % dp
            return Response(status=httplib.NOT_FOUND, body=body)

        body = self._format_response(self.link_set.get_items(int(dpid,16)))
        return (Response(content_type='application/json', body=body))

class restsaviapi(app_manager.RyuApp):
    _CONTEXTS = {
        'network': network.Network,
        'dpset': dpset.DPSet,
        'link_set': link_set.LinkSet,
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(restsaviapi, self).__init__(*args, **kwargs)
        self.nw = kwargs['network']
        self.dpset = kwargs['dpset']
        self.link_set = kwargs['link_set']
        wsgi = kwargs['wsgi']
        self.waiters = {}
	self.device = {}
        self.data = {}

        self.data['dpset'] = self.dpset
        self.data['link_set'] = self.link_set
        self.data['waiters'] = self.waiters
	self.data['device'] = self.device
 
        mapper = wsgi.mapper

        wsgi.registory['NetworkController'] = self.nw
        uri = '/v1.0/networks'
        mapper.connect('networks', uri,
                       controller=NetworkController, action='lists',
                       conditions=dict(method=['GET', 'HEAD']))

        uri += '/{network_id}'
        mapper.connect('networks', uri,
                       controller=NetworkController, action='create',
                       conditions=dict(method=['POST']))

        mapper.connect('networks', uri,
                       controller=NetworkController, action='update',
                       conditions=dict(method=['PUT']))

        mapper.connect('networks', uri,
                       controller=NetworkController, action='delete',
                       conditions=dict(method=['DELETE']))

        wsgi.registory['PortController'] = self.nw
        mapper.connect('networks', uri,
                       controller=PortController, action='lists',
                       conditions=dict(method=['GET']))

        uri += '/{dpid}_{port_id}'
        mapper.connect('ports', uri,
                       controller=PortController, action='create',
                       conditions=dict(method=['POST']))
        mapper.connect('ports', uri,
                       controller=PortController, action='update',
                       conditions=dict(method=['PUT']))

        mapper.connect('ports', uri,
                       controller=PortController, action='delete',
                       conditions=dict(method=['DELETE']))

        wsgi.registory['StatsController'] = self.data
        path = '/v1.0/stats'
        uri = path + '/switches'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_dpids',
                       conditions=dict(method=['GET']))

        uri = path + '/devices'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_devices',
                       conditions=dict(method=['GET']))

        uri = path + '/desc/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_desc_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/features/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_features',
                       conditions=dict(method=['GET']))


        uri = path + '/flow/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_flow_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/port/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_port_stats',
                       conditions=dict(method=['GET']))


        uri = path + '/flowentry'
        mapper.connect('stats', uri,
                       controller=StatsController, action='push_flow_entry',
                       conditions=dict(method=['POST']))
        uri = uri + '/clear/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='delete_flow_entry',
                       conditions=dict(method=['DELETE']))


        wsgi.registory['DiscoveryController'] = self.data
        path = '/v1.0/topology'
        uri = path + '/links'
        mapper.connect('topology', uri,
                       controller=DiscoveryController, action='get_links',
                       conditions=dict(method=['GET']))

        uri = path + '/switch/{dpid}/links'
        mapper.connect('topology', uri,
                       controller=DiscoveryController, action='get_switch_links',
                       conditions=dict(method=['GET']))

    def ip_to_str(self, addr):
        return '.'.join('%d' % ord(char) for char in addr)

    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)
        print 'stats_reply_handler:', msgs

        if msg.flags & dp.ofproto.OFPSF_REPLY_MORE:
            return
        del self.waiters[dp.id][msg.xid]
        lock.set()

    # edit(eliot)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        dst, src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)

        dpid = datapath.id
	src_str = haddr_to_str(src)
	dpid_str = dpid_to_str(dpid)

	# find the source
	if not src_str in self.device:
		self.device.setdefault(src_str, {})
		self.device[src_str]['ipv4'] = []
		self.device[src_str]['attachmentPoint'] = []
		ap = {}
		ap['switchDPID'] = dpid_str
		ap['port'] = msg.in_port
		self.device[src_str]['attachmentPoint'].append(ap)
	else:
		d = self.device[src_str]
		# Update attachment point
		aps = d['attachmentPoint']
#		exist = None
#		for ap in aps:
#			if ap['switchDPID'] == dpid_str and ap['port'] == msg.in_port:
#				exist = ap
#				break

#		if exist is None:
#			ap = {}
#			ap['switchDPID'] = dpid_str
#			ap['port'] = msg.in_port
#			aps.append(ap)

		# Update ip information
		if _eth_type == 0x0800:
			ipd = d['ipv4']
			src_ip, dst_ip = struct.unpack_from('!4s4s',buffer(msg.data), 26)
			src_ip_str = self.ip_to_str(src_ip)
			if not src_ip_str in set(ipd):
				ipd.append(src_ip_str)
			LOG.info("IPv4 update %s for %s", src_ip_str, src_str )

	
    # edit(eliot)
    def port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        datapath = msg.datapath
        ofproto = datapath.ofproto
        port_no = msg.desc.port_no
	dpid_str = dpid_to_str(datapath.id)

        if reason == ofproto.OFPPR_DELETE:
		LOG.info("rest port deleted %s(%s)", dpid_str, port_no)
		exist = None
		for mac in self.device.keys():
			aps = self.device[mac]['attachmentPoint']
			for ap in aps:
				if ap['switchDPID'] == dpid_str and ap['port'] == port_no:
					exist = mac
					break

		if not exist is None:
			del self.device[exist]
	        
        elif reason == ofproto.OFPPR_MODIFY:
            LOG.info("rest port modified %s", port_no)
        else:
            LOG.info("rest Illeagal port state %s %s", port_no, reason)

    @set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER)
    def desc_stats_reply_handler(self, ev):
        self.stats_reply_handler(ev)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        self.stats_reply_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        self.stats_reply_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
	self.packet_in_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
	self.port_status_handler(ev)
