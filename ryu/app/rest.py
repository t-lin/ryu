# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at private email ne jp>
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

import json
import httplib
from webob import Request, Response

from ryu.base import app_manager
from ryu.controller import network
from ryu.controller import flowvisor_cli
from ryu.controller import dpset
from ryu.controller import mac_to_port
from ryu.exception import NetworkNotFound, NetworkAlreadyExist
from ryu.exception import PortNotFound, PortAlreadyExist, PortUnknown
from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.exception import MacAddressDuplicated
from ryu.lib.mac import is_multicast, haddr_to_str
from ryu.lib import mac
from ryu.app.rest_nw_id import NW_ID_EXTERNAL
from ryu.ofproto import ofproto_v1_0 as ofproto

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

    def list_macs(self, req, network_id, **_kwargs):
        mac_list = []
        for macAddr in self.nw.list_macs(network_id):
            macStr = ""
            for byte in map(ord, macAddr): #Converts byte-wise mac addr to proper string
                macStr += "%X" % byte + "-"
            
            mac_list.append(macStr[:-1])
            
        body = json.dumps(mac_list)
        return Response(content_type='application/json', body=body)

    def add_mac(self, req, network_id, mac, **_kwargs):
        try:
            self.nw.add_mac(network_id, mac)
        except MacAddressDuplicated:
            return Response(status=409)
        else:
            return Response(status=200)

    def add_iface(self, req, network_id, iface_id, **_kwargs):
        try:
            self.nw.add_iface(network_id, iface_id)
        except MacAddressDuplicated:
            return Response(status=409)
        else:
            return Response(status=200)

    def del_mac(self, req, network_id, mac, **_kwargs):
        try:
            # 'network_id' not actually required
            # Kept to keep uri format similar to add_mac
            self.nw.del_mac(mac)
        except:
            return Response(status=500)
        else:
            return Response(status=200)

    def del_iface(self, req, network_id, iface_id, **_kwargs):
        try:
            # 'network_id' not actually required
            # Kept to keep uri format similar to add_iface
            self.nw.del_iface(iface_id)
        except:
            return Response(status=500)
        else:
            return Response(status=200)

    def delete(self, req, network_id, **_kwargs):
        try:
            self.nw.remove_network(network_id)
        except NetworkNotFound:
            return Response(status=404)

        return Response(status=200)

    def setPacketHandler(self, req, handler_id, **_kwargs):
        self.nw.setPacketHandler(int(handler_id))
        return Response(status=200)


class PortController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(PortController, self).__init__(req, link, data, **config)
        self.nw = data.get('nw')
        self.fv_cli = data.get('fv_cli')
        self.mac2port = data.get('mac2port')
        assert self.fv_cli is not None
        assert self.nw is not None
        assert self.mac2port is not None

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
            try:
                old_network_id = self.nw.get_network(int(dpid, 16), int(port_id))
            except PortUnknown:
                old_network_id = None

            self.fv_cli.updatePort(network_id, int(dpid, 16),
                                    int(port_id), True, old_network_id)
            self.nw.update_port(network_id, int(dpid, 16), int(port_id))
        except (NetworkNotFound, PortUnknown):
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
            self.fv_cli.deletePort(network_id, int(dpid, 16), int(port_id))
            
            # Find MAC that was associated with port and remove any other
            #    FlowSpace rules that may contain it
            macList = self.mac2port.mac_list(int(dpid, 16), int(port_id))
            for mac in macList:
                flowspace_ids = self.fv_cli.getFlowSpaceIDs(None, None, mac)

                for id in flowspace_ids:
                    ret = self.fv_cli.removeFlowSpace(id)
                    if (ret.find("success") == -1):
                        # Error, how to handle?
                        pass

                self.fv_cli.delFlowSpaceIDs(flowspace_ids)
                    
            self.nw.remove_port(network_id, int(dpid, 16), int(port_id))
        except (NetworkNotFound, PortNotFound):
            return Response(status=404)

        return Response(status=200)


class FlowVisorController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(FlowVisorController, self).__init__(req, link, data, **config)
        self.fv_cli = data.get('fv_cli')
        self.nw = data.get('nw')
        self.dpset = data.get('dpset')
        self.mac2port = data.get('mac2port')
        assert self.fv_cli is not None
        assert self.nw is not None
        assert self.dpset is not None
        assert self.mac2port is not None

    def listSlices(self, req, **_kwargs):
        body = self.fv_cli.listSlices()
        if (body.find("Slice 0") != -1):
            status = 200
        else:
            status = 500

        return Response(status=status, content_type='application/json', body=body)

    def createSlice(self, req, sliceName, ip, port):
        body = self.fv_cli.createSlice(sliceName, ip, port)
        if (body.find("success") != -1):
            status = 200
        elif (body.find("Cannot create slice with existing name") != -1):
            status = 409
        else:
            status = 500

        return Response(status=status, content_type='application/json', body=body)

    def deleteSlice(self, req, sliceName):
        body = self.fv_cli.deleteSlice(sliceName)
        if (body.find("success") != -1):
            status = 200
        elif (body.find("slice does not exist") != -1):
            status = 409
        else:
            status = 500

        return Response(status=status, content_type='application/json', body=body)

    # Delegate control of a network to the controller in charge of the specified slice
    def assignNetwork(self, req, sliceName, network_id):
        status = 200
        body = ""

        # Check if network has been assigned to another controller
        # If so, must unassign it from the other controller first
        slice = self.fv_cli.getSliceName(network_id)
        if slice:
            if (slice == sliceName):  # Should this result in an error instead?
                return Response(status=status)

            response = self.unassignNetwork(req, network_id)
            status = response.status_code
        
        if (status == 200) and (sliceName != self.fv_cli.defaultSlice):
            # Install FV rules to route packets to controller
            for (dpid, port) in self.nw.list_ports(network_id):
                for mac in self.mac2port.mac_list(dpid, port):
                    if not is_multicast(mac):
                        # Install rule for MAC for all EXTERNAL ports throughout network
                        for (dpid2, port2) in self.nw.list_ports(NW_ID_EXTERNAL):
                            if (dpid2 == dpid):
                                continue

                            body = self.fv_cli.addFlowSpace(sliceName, dpid2, port2, haddr_to_str(mac))
                            if (body.find("success") == -1):
                                status = 500
                                break

                            self.fv_cli.addFlowSpaceID(dpid2, port2, mac, int(body[9:]))

                        if (status == 500):
                            break

                        # Now install rule for the target switch 
                        body = self.fv_cli.addFlowSpace(sliceName, dpid, port, haddr_to_str(mac))
                        if (body.find("success") == -1):
                            # Error occured while attempting to install FV rule
                            status = 500
                            break

                        # Keep track of installed rules related to network
                        self.fv_cli.addFlowSpaceID(dpid, port, mac, int(body[9:]))
                            
                if (status == 500):
                    break

                # Now delete rules installed in the switches
                dp = self.dpset.get(dpid)
                if dp is not None:
                    dp.send_delete_all_flows()

        if (status == 500):
            # Error occured in the middle of installing rules
            # Previously installed rules be deleted
            self.unassignNetwork(req, network_id)

        if (status == 200):
            self.fv_cli.slice2nw_add(sliceName, network_id)

        return Response(status=status, content_type='application/json', body=body)

    def unassignNetwork(self, req, network_id):
        status = 200
        body = ""

        # Check if network has been assigned to a controller
        if self.fv_cli.getSliceName(network_id):
            # Remove FlowSpace rules associated with the network
            macs = self.nw.mac2net.list_macs(network_id)
            if macs is not None:
                for mac in macs:
                    flowspace_ids = self.fv_cli.getFlowSpaceIDs(None, None, mac)

                    for id in flowspace_ids:
                        body = self.fv_cli.removeFlowSpace(id)
                        if (body.find("success") == -1):
                            status = 500
                            break

                        self.fv_cli.delFlowSpaceIDs(id)
            else:
                status = 404

            # Now delete rules installed in relevant switches
            for (dpid, port) in self.nw.list_ports(network_id):
                dp = self.dpset.get(dpid)
                if dp is not None:
                    dp.send_delete_all_flows()

            if (status == 200):
                self.fv_cli.slice2nw_del(network_id)
        else:
            # Should this result in an error status and message instead?
            body = "success!"

        return Response(status=status, content_type='application/json', body=body)

class SimpleSwitch(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SimpleSwitch, self).__init__(req, link, data, **config)
        self.mac_to_port = data.get('mac2port')
        assert self.mac_to_port is not None

        # For http requests
        address = 0# do later
        self.host = '10.10.10.81'
        self.port = 8090
        self.url_prefix = '/v1.0'

        #self.output_url = '/%(dpid)s/output/%(buffer_id)s_%(in_port)s_%(out_port)s'
        #self.addFlow_url = '/%(dpid)s/flowmod/%(in_port)s_%(dst)s_%(out_port)s'
        #self.drop_url = '/%(dpid)s/drop/%(buffer_id)s_%(in_port)s'
        self.output_url = '/%s/output/%s_%s_%s'
        self.addFlow_url = '/%s/flowmod/%s_%s_%s'
        self.drop_url = '/%s/drop/%s_%s'

    def controllerAction(self, action, method):
        conn = httplib.HTTPConnection(self.host, self.port)

        url = self.url_prefix + '/packetAction' + action
        print "SENDING BACK DOWN TO CONTROLLER: %s" % url
        conn.request(method, url)
        res = conn.getresponse()
        if res.status in (httplib.OK,
                          httplib.CREATED,
                          httplib.ACCEPTED,
                          httplib.NO_CONTENT):
            return res

        raise httplib.HTTPException(
            res, 'code %d reason %s' % (res.status, res.reason),
            res.getheaders(), res.read())

    def packet_in(self, req, dpid, buffer_id, src, dst, in_port):
        print "PACKET HANDLER FUNCTION"
        self.mac_to_port.dpid_add(dpid)

        # learn a mac address to avoid FLOOD next time.
        #self.mac_to_port[dpid][src] = in_port
        self.mac_to_port.port_add(dpid, in_port, src)
        broadcast = (dst == mac.BROADCAST) or mac.is_multicast(dst)

        if broadcast:
            out_port = ofproto.OFPP_FLOOD
        elif src != dst:
            #if dst in self.mac_to_port[dpid]:
                #out_port = self.mac_to_port[dpid][dst]
            out_port = self.mac_to_port.port_get(dpid, dst)
            if not out_port:
                out_port = ofproto.OFPP_FLOOD
        else:
            #self._drop_packet(msg)
            self.controllerAction(self.drop_url % (dpid, buffer_id, in_port), 'DELETE')
            return

        # install a flow to avoid packet_in next time
        if broadcast or (out_port != ofproto.OFPP_FLOOD):
            #self.add_flow(datapath, msg.in_port, dst, actions)
            self.controllerAction(self.addFlow_url % (dpid, in_port, dst, out_port), 'PUT')

        # Output packet
        self.controllerAction(self.output_url % (dpid, buffer_id, in_port, out_port), 'PUT')


class restapi(app_manager.RyuApp):
    _CONTEXTS = {
        'network': network.Network,
        'wsgi': WSGIApplication,
        'fv_cli': flowvisor_cli.FlowVisor_CLI,
        'dpset': dpset.DPSet,
        'mac2port': mac_to_port.MacToPortTable,
        }

    def __init__(self, *args, **kwargs):
        super(restapi, self).__init__(*args, **kwargs)
        self.nw = kwargs['network']
        self.fv_cli = kwargs['fv_cli']
        wsgi = kwargs['wsgi']
        self.dpset = kwargs['dpset']
        self.mac2port = kwargs['mac2port']
        mapper = wsgi.mapper

        # Change packet handler
        wsgi.registory['NetworkController'] = self.nw
        mapper.connect('networks', '/v1.0/packethandler/{handler_id}',
                       controller=NetworkController, action='setPacketHandler',
                       conditions=dict(method=['PUT']))
        
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

        # List macs associated with a network
        mapper.connect('networks', uri + '/macs',
                       controller=NetworkController, action='list_macs',
                       conditions=dict(method=['GET']))

        # Associate a MAC address with a network
        mapper.connect('networks', uri + '/macs/{mac}',
                       controller=NetworkController, action='add_mac',
                       conditions=dict(method=['PUT']))

        # Associate an interface with a network
        mapper.connect('networks', uri + '/iface/{iface_id}',
                       controller=NetworkController, action='add_iface',
                       conditions=dict(method=['PUT']))

        # Dissociate a MAC address with a network
        mapper.connect('networks', uri + '/macs/{mac}',
                       controller=NetworkController, action='del_mac',
                       conditions=dict(method=['DELETE']))

        # Dissociate an interface with a network
        mapper.connect('networks', uri + '/iface/{iface_id}',
                       controller=NetworkController, action='del_iface',
                       conditions=dict(method=['DELETE']))

        wsgi.registory['PortController'] = {"nw" : self.nw,
                                            "fv_cli" : self.fv_cli,
                                            "mac2port" : self.mac2port}
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

        # FlowVisor related APIs
        wsgi.registory['FlowVisorController'] = {'fv_cli' : self.fv_cli,
                                                 'nw' : self.nw,
                                                 'dpset' : self.dpset,
                                                 'mac2port' : self.mac2port}
        uri = '/v1.0/flowvisor'
        mapper.connect('flowvisor', uri,
                       controller=FlowVisorController, action='listSlices',
                       conditions=dict(method=['GET']))

        mapper.connect('flowvisor', uri + '/{sliceName}',
                       controller=FlowVisorController, action='deleteSlice',
                       conditions=dict(method=['DELETE']))

        mapper.connect('flowvisor', uri + '/{sliceName}_{ip}_{port}',
                       controller=FlowVisorController, action='createSlice',
                       conditions=dict(method=['POST']))

        mapper.connect('flowvisor', uri + '/{sliceName}/assign/{network_id}',
                       controller=FlowVisorController, action='assignNetwork',
                       conditions=dict(method=['PUT']))

        mapper.connect('flowvisor', uri + '/unassign/{network_id}',
                       controller=FlowVisorController, action='unassignNetwork',
                       conditions=dict(method=['PUT']))

        # APIs for the application
        wsgi.registory['SimpleSwitch'] = {'mac2port' : self.mac2port}
        uri = '/v1.0/app'
        mapper.connect('application', uri + '/packet_in/{dpid}/{buffer_id}/{src}_{dst}_{in_port}',
                       controller=SimpleSwitch, action='packet_in',
                       conditions=dict(method=['PUT']))
