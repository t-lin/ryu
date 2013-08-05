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
from ryu.controller import dpset
from ryu.controller import link_set
from ryu.ofproto import ofproto_v1_0
from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.lib import dpid as lib_dpid


LOG = logging.getLogger('ryu.app.savi_discovery')

# REST API for discovery status
#
# get all the links
# GET /v1.0/topology/links
#
# get the links connected <dpid>
# GET /v1.0/topology/switch/dpid>/links
#
# where
# <dpid>: datapath id in 16 hex
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

class RestDiscoveryApi(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'link_set': link_set.LinkSet,
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(RestDiscoveryApi, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        self.link_set = kwargs['link_set']
        wsgi = kwargs['wsgi']
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['link_set'] = self.link_set
        mapper = wsgi.mapper

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
