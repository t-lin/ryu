# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at private email ne jp>
# Copyright (C) 2012, The SAVI Project.
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
import sys
import struct
import logging
import time
from webob import Request, Response

from ryu.base import app_manager
from ryu.controller import network
from ryu.controller import flowvisor_cli
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller import link_set
from ryu.controller import mac_to_port
from ryu.controller import mac_to_network
from ryu.controller import api_db
from ryu.controller import port_bond
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib import ofctl_v1_0
from ryu.exception import NetworkNotFound, NetworkAlreadyExist
from ryu.exception import PortNotFound, PortAlreadyExist, PortUnknown
from ryu.exception import BondAlreadyExist, BondNotFound, BondNetworkMismatch, BondPortNotFound, BondPortAlreadyBonded
from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.exception import MacAddressDuplicated, MacAddressNotFound
from ryu.lib.dpid import dpid_to_str
from ryu.lib import dpid as lib_dpid
from ryu.lib.mac import is_multicast, haddr_to_str, haddr_to_bin, ipaddr_to_bin, ipaddr_to_str
from ryu.app.rest_nw_id import NW_ID_EXTERNAL

LOG = logging.getLogger('ryu.app.rest')

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
        self.nw = data.get('nw')
        self.mac2net = data.get('mac2net')
        self.api_db = data.get('api_db')
        self.mac2port = data.get('mac2port')

        assert self.nw is not None
        assert self.mac2net is not None
        assert self.api_db is not None
        assert self.mac2port is not None

    def create(self, req, network_id, **_kwargs):
        try:
            self.nw.create_network(network_id)
            self.api_db.createNetwork(network_id)
        except NetworkAlreadyExist:
            return Response(status=200)
        else:
            return Response(status=200)

    def update(self, req, network_id, **_kwargs):
        self.nw.update_network(network_id)
        self.api_db.updateNetwork(network_id)
        return Response(status=200)

    def lists(self, req, **_kwargs):
        body = json.dumps(self.nw.list_networks())
        return Response(content_type='application/json', body=body)

    def list_macs(self, req, network_id, **_kwargs):
        mac_list = []
        for macAddr in self.mac2net.list_macs(network_id):
            mac_list.append(haddr_to_str(macAddr))

        body = json.dumps(mac_list)
        return Response(content_type='application/json', body=body)

    def add_mac(self, req, network_id, mac, **_kwargs):
        try:
            # Must convert MAC address into ASCII char types
            charMAC = haddr_to_bin(mac)

            self.mac2net.add_mac(charMAC, network_id, NW_ID_EXTERNAL)
            self.api_db.addMAC(network_id, mac)
        except MacAddressDuplicated:
            return Response(status=200)
        else:
            return Response(status=200)

    def add_ip(self, req, mac, ip, dpid, port_id, **_kwargs):
        try:
            self.mac2port.dpid_add(int(dpid, 16))
            self.mac2port.port_add(int(dpid, 16), int(port_id), haddr_to_bin(mac), ipaddr_to_bin(ip))
        except ValueError:
            print 'Invalid ip address format. Check the ip you are registering: %s' % ip
            return Response(status=500)
        except:
            return Response(status=500)
        else:
            return Response(status=200)

    def add_iface(self, req, network_id, iface_id, **_kwargs):
        try:
            self.nw.add_iface(network_id, iface_id)
        except MacAddressDuplicated:
            return Response(status=200)
        else:
            return Response(status=200)

    def del_mac(self, req, network_id, mac, **_kwargs):
        try:
            # 'network_id' not actually required
            # Kept to keep uri format similar to add_mac
            # Must convert MAC address into ASCII char types
            charMAC = haddr_to_bin(mac)

            self.mac2net.del_mac(charMAC)
            self.api_db.delMAC(mac)
        except MacAddressNotFound:
            return Response(status=200)
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
            self.api_db.deleteNetwork(network_id)
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
        self.api_db = data.get('api_db')

        assert self.fv_cli is not None
        assert self.nw is not None
        assert self.mac2port is not None
        assert self.api_db is not None

    def create(self, req, network_id, dpid, port_id, **_kwargs):
        try:
            datapath_id = int(dpid, 16)
            port = int(port_id)

            if port > 0:
                if not self.nw.same_network(datapath_id, NW_ID_EXTERNAL, port):
                    self.nw.create_port(network_id, datapath_id, port)
                    self.api_db.createPort(network_id, dpid, port_id)
                else:
                    # If a port has been registered as external, leave it be
                    pass
            else:
                # Don't raise exception or else q-agt may crash and stop
                pass
        except NetworkNotFound:
            return Response(status=404)
        except PortAlreadyExist:
            return Response(status=200)

        return Response(status=200)

    def update(self, req, network_id, dpid, port_id, **_kwargs):
        try:
            try:
                old_network_id = self.nw.get_network(int(dpid, 16), int(port_id))
            except PortUnknown:
                old_network_id = None

            # Updating an existing port whose network has changed
            if self.fv_cli.getSliceName(old_network_id) or (old_network_id == NW_ID_EXTERNAL):
                flowspace_ids = self.fv_cli.getFlowSpaceIDs(int(dpid,16), int(port_id))
                for id in flowspace_ids:
                    ret = self.fv_cli.removeFlowSpace(id)
                    if (ret.find("success") != -1):
                        self.fv_cli.delFlowSpaceID(id)
                        self.api_db.delFlowSpaceID(id)
                    else:
                        # Error, how to handle?
                        continue

            self.nw.update_port(network_id, int(dpid, 16), int(port_id))
            self.api_db.updatePort(network_id, dpid, port_id)
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
            if self.fv_cli.getSliceName(network_id) or (network_id == NW_ID_EXTERNAL):
                try:
                    flowspace_ids = self.fv_cli.getFlowSpaceIDs(int(dpid,16), int(port_id))
                except PortUnknown:
                    raise PortNotFound(dpid=dpid, port=port, network_id=network_id)
                else:
                    for id in flowspace_ids:
                        ret = self.fv_cli.removeFlowSpace(id)
                        if (ret.find("success") != -1):
                            self.fv_cli.delFlowSpaceID(id)
                            self.api_db.delFlowSpaceID(id)
                        else:
                            # Error, how to handle?
                            continue

                # Should we delete entries from the switch's flow table?

            # If network_id isn't external, assume the port is connected to one or
            #   more hosts about to be deleted. Thus, delete their MACs from network.
            # Once full topology is known, we can do an actual check
            if network_id != NW_ID_EXTERNAL:
                # Find MAC(s) that was associated with port and remove any other
                #    FlowSpace rules that may contain it
                macList = self.mac2port.mac_list(int(dpid, 16), int(port_id))
                for mac in macList:
                    flowspace_ids = self.fv_cli.getFlowSpaceIDs(None, None, mac)

                    for id in flowspace_ids:
                        ret = self.fv_cli.removeFlowSpace(id)
                        if (ret.find("success") != -1):
                            self.fv_cli.delFlowSpaceID(id)
                            self.api_db.delFlowSpaceID(id)
                        else:
                            # Error, how to handle?
                            continue

            self.nw.remove_port(network_id, int(dpid, 16), int(port_id))
            self.api_db.deletePort(network_id, dpid, port_id)
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
        self.mac2net = data.get('mac2net')
        self.api_db = data.get('api_db')

        assert self.fv_cli is not None
        assert self.nw is not None
        assert self.dpset is not None
        assert self.mac2port is not None
        assert self.mac2net is not None
        assert self.api_db is not None

    def listSlices(self, req, **_kwargs):
        body = self.fv_cli.listSlices()
        if (body.find("Slice 0") != -1):
            status = 200
        else:
            status = 500

        return Response(status=status, content_type='application/json', body=body)

    def listFlowSpace(self, req, **_kwargs):
        body = self.fv_cli.listFlowSpace()
        # Should always be a rule 0 (default rule) installed
        if (body.find("rule 0") != -1):
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

        # Verify slice actually exists first (Patch for FV bug that returns success
        # when user attempts to assign a network to a non-existent slice)
        if (self.fv_cli.listSlices().find(sliceName) == -1):
            status = 404
            body = "Slice does not exist!\n"

        # Check if network has been assigned to another controller
        # If so, must unassign it from the other controller first
        slice = self.fv_cli.getSliceName(network_id)
        if (status == 200) and slice:
            if (slice == sliceName):  # Should this result in an error instead?
                return Response(status=status)

            response = self.unassignNetwork(req, network_id)
            status = response.status_code

        if (status == 200) and (sliceName != self.fv_cli.defaultSlice):
            self.fv_cli.slice2nw_add(sliceName, network_id)
            self.api_db.assignNetToSlice(sliceName, network_id)

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
                            self.api_db.addFlowSpaceID(hex(dpid2), port2, haddr_to_str(mac), int(body[9:]))

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
                        self.api_db.addFlowSpaceID(hex(dpid), port, haddr_to_str(mac), int(body[9:]))

                if (status == 500):
                    break

                # Now delete rules installed in the switches
                dp = self.dpset.get(dpid)
                if dp is not None:
                    dp.send_delete_all_flows()

        if (status == 500):
            # Error occured in the middle of installing rules
            # Delete previously installed rules
            self.unassignNetwork(req, network_id)

        return Response(status=status, content_type='application/json', body=body)

    def unassignNetwork(self, req, network_id):
        status = 200
        body = ""

        # Check if network has been assigned to a controller
        sliceName = self.fv_cli.getSliceName(network_id)
        if sliceName:
            # Remove network UUID from slice2nw first to prevent packets which
            # arrive during removal process from triggering FlowSpace add events in app
            self.fv_cli.slice2nw_del(network_id)
            self.api_db.removeNetFromSlice(network_id)

            # Remove FlowSpace rules associated with the network
            macs = self.mac2net.list_macs(network_id)
            if macs is not None:
                for mac in macs:
                    flowspace_ids = self.fv_cli.getFlowSpaceIDs(None, None, mac)

                    for id in flowspace_ids:
                        body = self.fv_cli.removeFlowSpace(id)
                        if (body.find("success") == -1):
                            status = 500
                            break

                        self.fv_cli.delFlowSpaceID(id)
                        self.api_db.delFlowSpaceID(id)
            else:
                status = 404

            # Now delete rules installed in relevant switches
            for (dpid, port) in self.nw.list_ports(network_id):
                dp = self.dpset.get(dpid)
                if dp is not None:
                    dp.send_delete_all_flows()

            if (status != 200):
                # Something went wrong. Re-add network UUID in slice2nw
                self.fv_cli.slice2nw_add(sliceName, network_id)
                self.api_db.assignNetToSlice(sliceName, network_id)
        else:
            # Should this result in an error status and message instead?
            body = "success!"

        return Response(status=status, content_type='application/json', body=body)


class PortBondController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(PortBondController, self).__init__(req, link, data, **config)
        self.port_bond = data.get('port_bond')
        self.api_db = data.get('api_db')

        assert self.port_bond is not None
        assert self.api_db is not None

    def list_bonds(self, req):
        body = json.dumps(self.port_bond.list_bonds())
        return Response(status=200, content_type='application/json', body=body)

    def create_bond(self, req, dpid, network_id):
        try:
            bond_id = self.port_bond.create_bond(int(dpid, 16), network_id)
            body = json.dumps(bond_id)
            self.api_db.createBond(bond_id, dpid, network_id)
        except BondAlreadyExist:
            body = "Bond ID already exists"
            return Response(status=409, body=body)

        return Response(status=200, content_type='application/json', body=body)

    def delete_bond(self, req, bond_id):
        self.port_bond.delete_bond(bond_id)
        self.api_db.deleteBond(bond_id)

        return Response(status=200)

    def add_port(self, req, bond_id, port):
        try:
            self.port_bond.add_port(bond_id, int(port))
            self.api_db.addPort_bond(bond_id, port)
        except BondNetworkMismatch:
            body = "Bond's network ID does not match port's network ID\n"
        except (PortNotFound, BondPortAlreadyBonded):
            body = "Unavailable port (Port does not exist or port already bonded)\n"
        except BondNotFound:
            body = "Bond ID not found\n"
        else:
            return Response(status=200)

        return Response(status=403, body=body)

    def del_port(self, req, bond_id, port):
        try:
            self.port_bond.del_port(bond_id, int(port))
            self.api_db.deletePort_bond(bond_id, port)
        except BondPortNotFound:
            body = "Port not found in bond\n"
        except BondNotFound:
            body = "Bond ID not found \n"
        else:
            return Response(status=200)

        return Response(status=404, body=body)

    def list_ports(self, req, bond_id):
        body = self.port_bond.ports_in_bond(bond_id)
        if body is not None: # Explicitly use 'None' as body can be an empty list
            body = json.dumps(body)
        else:
            body = "Bond does not exist\n"

        return Response(status=200, content_type='application/json', body=body)

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


class restapi(app_manager.RyuApp):
    _CONTEXTS = {
        'network': network.Network,
        'wsgi': WSGIApplication,
        'link_set': link_set.LinkSet,
        'fv_cli': flowvisor_cli.FlowVisor_CLI,
        'dpset': dpset.DPSet,
        'mac2port': mac_to_port.MacToPortTable,
        'mac2net': mac_to_network.MacToNetwork,
        'api_db': api_db.API_DB,
        'port_bond': port_bond.PortBond
    }

    def __init__(self, *args, **kwargs):
        super(restapi, self).__init__(*args, **kwargs)
        self.nw = kwargs['network']
        self.link_set = kwargs['link_set']
        self.fv_cli = kwargs['fv_cli']
        wsgi = kwargs['wsgi']
        self.dpset = kwargs['dpset']
        self.mac2port = kwargs['mac2port']
        self.mac2net = kwargs['mac2net']
        self.api_db = kwargs['api_db']
        self.port_bond = kwargs['port_bond']
        self.waiters = {}
        self.device = {}
        self.data = {}


        self.data['dpset'] = self.dpset
        self.data['link_set'] = self.link_set
        self.data['waiters'] = self.waiters
        self.data['device'] = self.device

        mapper = wsgi.mapper

        self.is64bit = (sys.maxsize > 2**32)

        # Change packet handler
        wsgi.registory['NetworkController'] = { 'nw' : self.nw,
                                                'mac2net' : self.mac2net,
                                                'api_db' : self.api_db,
                                                'mac2port' : self.mac2port }

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

        # Broadcast-less related APIs
        mapper.connect('networks', uri + '/macipportdp/{mac}/{ip}/{dpid}_{port_id}',
                       controller=NetworkController, action='add_ip',
                       conditions=dict(method=['PUT']))

        # PortController related APIs
        wsgi.registory['PortController'] = {'nw' : self.nw,
                                            'fv_cli' : self.fv_cli,
                                            'mac2port' : self.mac2port,
                                            'api_db' : self.api_db    }
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
                                                 'mac2port' : self.mac2port,
                                                 'mac2net' : self.mac2net,
                                                 'api_db' : self.api_db     }
        uri = '/v1.0/flowvisor'
        mapper.connect('flowvisor', uri,
                       controller=FlowVisorController, action='listSlices',
                       conditions=dict(method=['GET']))

        mapper.connect('flowvisor', uri + '/flowspace',
                       controller=FlowVisorController, action='listFlowSpace',
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

        # Port Bonding related APIs
        wsgi.registory['PortBondController'] = {'port_bond': self.port_bond,
                                                'api_db' : self.api_db      }
        self.port_bond.setNetworkObjHandle(self.nw)

        uri = '/v1.0/port_bond'
        mapper.connect('port_bond', uri,
                       controller=PortBondController, action='list_bonds',
                       conditions=dict(method=['GET']))

        mapper.connect('port_bond', uri + '/{dpid}_{network_id}',
                       controller=PortBondController, action='create_bond',
                       conditions=dict(method=['POST']))

        mapper.connect('port_bond', uri + '/{bond_id}',
                       controller=PortBondController, action='delete_bond',
                       conditions=dict(method=['DELETE']))

        mapper.connect('port_bond', uri + '/{bond_id}/{port}',
                       controller=PortBondController, action='add_port',
                       conditions=dict(method=['PUT']))

        mapper.connect('port_bond', uri + '/{bond_id}/{port}',
                       controller=PortBondController, action='del_port',
                       conditions=dict(method=['DELETE']))

        mapper.connect('port_bond', uri + '/{bond_id}',
                       controller=PortBondController, action='list_ports',
                       conditions=dict(method=['GET']))

        self.loadDBContents()

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
    #        exist = None
    #        for ap in aps:
    #            if ap['switchDPID'] == dpid_str and ap['port'] == msg.in_port:
    #                exist = ap
    #                break

    #        if exist is None:
    #            ap = {}
    #            ap['switchDPID'] = dpid_str
    #            ap['port'] = msg.in_port
    #            aps.append(ap)

            # Update ip information
            if _eth_type == 0x0800:
                ipd = d['ipv4']
                src_ip, dst_ip = struct.unpack_from('!4s4s',buffer(msg.data), 26)
                src_ip_str = self.ip_to_str(src_ip)
                if not src_ip_str in set(ipd):
                    ipd.append(src_ip_str)
                #LOG.info("IPv4 update %s for %s", src_ip_str, src_str )


    # edit(eliot)
    def port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        datapath = msg.datapath
        ofproto = datapath.ofproto
        port_no = msg.desc.port_no
        dpid_str = dpid_to_str(datapath.id)

        if reason == ofproto.OFPPR_DELETE:
        #LOG.info("rest port deleted %s(%s)", dpid_str, port_no)
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

    # If any previous API calls are stored in DB, reload them now
    def loadDBContents(self):
        networks = self.api_db.getNetworks()
        ports = self.api_db.getPorts()
        macs = self.api_db.getMACs()
        bonds = self.api_db.getBonds()
        flowspace = self.api_db.getFlowSpace()
        net2slice = self.api_db.getDelegatedNets()

        for network_id in networks:
            self.nw.create_network(network_id)

        for (bond_id, dpid, network_id) in bonds:
            self.port_bond.create_bond(int(dpid, 16), network_id, bond_id)

        for (network_id, dpid, port_num, bond_id) in ports:
            self.nw.create_port(network_id, int(dpid, 16), int(port_num))
            if bond_id:
                self.port_bond.add_port(bond_id, int(port_num))

        for (network_id, mac_address) in macs:
            self.mac2net.add_mac(haddr_to_bin(mac_address), network_id, NW_ID_EXTERNAL)

        for (id, dpid, port_num, mac_address) in flowspace:
            if (self.is64bit):
                dpid = int(dpid[2:], 16)
            else:
                dpid = int(dpid[2:-1], 16)
            self.fv_cli.addFlowSpaceID(dpid, port_num, haddr_to_bin(mac_address), id)

        for (network_id, slice) in net2slice:
            self.fv_cli.slice2nw_add(slice, network_id)

