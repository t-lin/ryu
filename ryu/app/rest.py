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
from webob import Request, Response

from ryu.base import app_manager
from ryu.controller import network
from ryu.controller import flowvisor_cli
from ryu.controller import dpset
from ryu.controller import mac_to_port
from ryu.controller import mac_to_network
from ryu.controller import api_db
from ryu.controller import port_bond
from ryu.exception import NetworkNotFound, NetworkAlreadyExist
from ryu.exception import PortNotFound, PortAlreadyExist, PortUnknown
from ryu.exception import BondAlreadyExist, BondNotFound, BondNetworkMismatch, BondPortNotFound, BondPortAlreadyBonded
from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.exception import MacAddressDuplicated, MacAddressNotFound
from ryu.lib.mac import is_multicast, haddr_to_str, haddr_to_bin
from ryu.app.rest_nw_id import NW_ID_EXTERNAL

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
        self.nw = data.get('nw')
        self.mac2net = data.get('mac2net')
        self.api_db = data.get('api_db')

        assert self.nw is not None
        assert self.mac2net is not None
        assert self.api_db is not None

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


class restapi(app_manager.RyuApp):
    _CONTEXTS = {
        'network': network.Network,
        'wsgi': WSGIApplication,
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
        self.fv_cli = kwargs['fv_cli']
        wsgi = kwargs['wsgi']
        self.dpset = kwargs['dpset']
        self.mac2port = kwargs['mac2port']
        self.mac2net = kwargs['mac2net']
        self.api_db = kwargs['api_db']
        self.port_bond = kwargs['port_bond']
        mapper = wsgi.mapper
        
        self.is64bit = (sys.maxsize > 2**32)

        # Change packet handler
        wsgi.registory['NetworkController'] = { 'nw' : self.nw,
                                                'mac2net' : self.mac2net,
                                                'api_db' : self.api_db }
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

