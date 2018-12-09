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
from ryu.controller import link_set
from ryu.controller import dpset
from ryu.controller import mac_to_port
from ryu.lib.dpid import dpid_to_str
from ryu.lib import dpid as lib_dpid
from ryu.lib.mac import haddr_to_str, haddr_to_bin
from ryu.app.wsgi import ControllerBase, WSGIApplication


LOG = logging.getLogger('ryu.app.rest_savi')

## TODO:XXX
## define db interface and store those information into db

# REST API
# NOTE: These APIs deal with DPIDs returned in hex format
#       Conversely, ofctl_rest uses DPIDs in integer format

## Retrieve topology
#
# get all the links
# GET /topology/links
#
# get all the switches
# GET /topology/switches
#
# get the links connected <dpid>
# GET /topology/switch/<dpid>/links
#
# get ingress port of a MAC address
# GET /topology/mac/<mac>
#
# get latency estimate of a port
# GET /topology/stats/<dpid>_<port>
#
class DiscoveryController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(DiscoveryController, self).__init__(req, link, data, **config)
        self.dpset = data['dpset']
        self.link_set = data['link_set']
        self.mac2ext_port = data['mac2ext_port']
        self.ofsniff = data['ofsniff']
        self.dpid2endpoint = data['dpid2endpoint']

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

    def get_switches(self, req, **_kwargs):
        dp_list = []
        for dpid in self.dpset.dps.keys():
            dp_list.append(lib_dpid.dpid_to_str(dpid))
        body = json.dumps(dp_list)
        return Response(content_type='application/json', body=body)

    def get_switch_links(self, req, dpid):
        dp = self.dpset.get(int(dpid,16))
        if dp is None:
            body = 'dpid %s is not found\n' % dp
            return Response(status=httplib.NOT_FOUND, body=body)

        body = self._format_response(self.link_set.get_items(int(dpid,16)))
        return (Response(content_type='application/json', body=body))

    def get_ingress_port(self, req, mac):
        body = None
        mac_bin = haddr_to_bin(mac)
        for dpid in self.mac2ext_port.mac_to_port.keys():
            port = self.mac2ext_port.port_get(dpid, mac_bin)
            if port:
                #print "ingress port found: dpid = %016x and port = %s" % (dpid, port)
                body = {"dpid": lib_dpid.dpid_to_str(dpid), "port": port}
                break

        #if body is None:
        #   body = "Ingress port for %s not found" % mac

        body = json.dumps(body)
        return Response(content_type='application/json', body=body)

    def get_port_stats(self, req, dpid, port):
        if self.ofsniff.isSniffing():
            dpid = int(dpid, 16)
            port = int(port)

            if dpid not in self.dpid2endpoint.keys():
                body = 'dpid %s is not found\n' % dpid
                return Response(status=httplib.NOT_FOUND, body=body)

            endpoint = self.dpid2endpoint[dpid]
            body = {'avg': self.ofsniff.getLinkLatAvg(endpoint, port),
                    'var': self.ofsniff.getLinkLatVar(endpoint, port),
                    'med': self.ofsniff.getLinkLatMed(endpoint, port)}

            body = json.dumps(body) + '\n'
        else:
            body = "Sniff Loop not started\n"
            return Response(status=httplib.INTERNAL_SERVER_ERROR, body=body)

        return Response(content_type='application/json', body=body)

class RestDiscoveryApi(app_manager.RyuApp):
    _CONTEXTS = {
        'link_set': link_set.LinkSet,
        'wsgi': WSGIApplication,
        'mac2ext_port': mac_to_port.MacToPortTable,
    }

    def __init__(self, *args, **kwargs):
        super(RestDiscoveryApi, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        self.link_set = kwargs['link_set']
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}

        self.data['dpset'] = self.dpset
        self.data['link_set'] = self.link_set
        self.data['waiters'] = self.waiters
        self.data['mac2ext_port'] = kwargs['mac2ext_port']

        # OFSniff class and metadata handles (defined in discovery.py)
        # If this app runs, it's expected that discovery.py is also running
        self.data['ofsniff'] = kwargs['ofsniff']
        self.data['dpid2endpoint'] = kwargs['dpid2endpoint']

        mapper = wsgi.mapper

        wsgi.registory['DiscoveryController'] = self.data
        path = '/topology'
        uri = path + '/links'
        mapper.connect('topology', uri,
                       controller=DiscoveryController, action='get_links',
                       conditions=dict(method=['GET']))

        mapper.connect('topology', path + '/switches',
                       controller=DiscoveryController, action='get_switches',
                       conditions=dict(method=['GET']))

        uri = path + '/switch/{dpid}/links'
        mapper.connect('topology', uri,
                       controller=DiscoveryController, action='get_switch_links',
                       conditions=dict(method=['GET']))

        mapper.connect('topology', path + '/mac/{mac}',
                       controller=DiscoveryController, action='get_ingress_port',
                       conditions=dict(method=['GET']))

        uri = path + '/stats/{dpid}_{port}'
        mapper.connect('topology', uri,
                       controller=DiscoveryController, action='get_port_stats',
                       conditions=dict(method=['GET']))
