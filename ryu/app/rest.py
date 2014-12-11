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
import socket
import sys
from webob import Request, Response

from ryu.base import app_manager
from ryu.controller import network
from ryu.exception import NetworkNotFound, NetworkAlreadyExist
from ryu.exception import PortNotFound, PortAlreadyExist
from ryu.app.wsgi import ControllerBase, WSGIApplication

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

array_id = []
array_max_rate = []
array_min_rate = []
array_ip = []
array_port = []

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



class QoSController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(QoSController, self).__init__(req, link, data, **config)
        self.host = "10.12.13.15"
        self.port = 6634
        self.port_name = 'p1'
        self.max_rate = 30000000
        self.min_rate = 30000000

    def test(self, req, port_name, max_rate, min_rate):
        print "\nport_name: %s\n"  %port_name
        print "\nmax_rate: %s\n"  %max_rate
        print "\nmin_rate: %s\n"  %min_rate
        array_id.append(port_name)
        array_max_rate.append(max_rate)
        array_min_rate.append(min_rate)

        i = 0
        for id_element in array_id:
            print "i " + str(i)
            print "id element is " + id_element
            print "max_rate is " + array_max_rate[i]
            print "min_rate is " + array_min_rate[i]
            i=i+1

    def clear(self, req, port_name):
        self.port_name = port_name
        i=0
        found = False
        for id_element in array_id:
            if(id_element == port_name):
                found = True
                self.host = array_ip[i]
                self.port = int(array_port[i])
                print "ip is " + array_ip[i]
                print "port is " + array_port[i]
            i = i + 1
        #if ~found:
        #    print "not found using default"
        #    self.host = "10.12.13.15"
        #    self.port = 6634

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))

        s.send(json.dumps({"method":"monitor", "params":["Open_vSwitch", None,{"Port":{"columns":["name","qos"]},"QoS":{"columns":["external_ids","other_config","queues","type"]},"Queue":{"columns":[]},"Open_vSwitch":{"columns":["cur_cfg"]}}], "id":"0"}))
        result = json.loads(s.recv(32768))
        print "port req <========\n%s\n\n" % str(result)
        db_uuid = result['result']['Open_vSwitch'].keys()[0]
        print "db uuid is %s" % db_uuid

        s.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))

        found = 0
        i = 0
        for port in result['result']['Port'].values():
            if(port['new']['name'] == self.port_name):
               port_uuid = result['result']['Port'].keys()[i]
               found = 1
            i=i+1
        if found:
            print "port uuid \n%s\n\n" %port_uuid
        else:
            print "port not found !!!"

        s.send(json.dumps({"method":"transact", "params":["Open_vSwitch",{"row":{"qos":["set",[]]},"table":"Port","where":[["_uuid","==",["uuid",port_uuid]]],"op":"update"},{"mutations":[["next_cfg","+=",1]],"table":"Open_vSwitch","where":[["_uuid","==",["uuid", db_uuid]]],"op":"mutate"},{"columns":["next_cfg"],"table":"Open_vSwitch","where":[["_uuid","==",["uuid",db_uuid]]],"op":"select"},{"comment":"ovs-vsctl: ovs-vsctl -v clear port p1 qos","op":"comment"}], "id":"1"}))

        s.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))

        for qos_row in result['result']['QoS'].keys():
            s.send(json.dumps({"method":"transact", "params":["Open_vSwitch",{"table":"QoS","where":[["_uuid","==",["uuid",qos_row]]],"op":"delete"},{"mutations":[["next_cfg","+=",1]],"table":"Open_vSwitch","where":[["_uuid","==",["uuid",db_uuid]]],"op":"mutate"},{"columns":["next_cfg"],"table":"Open_vSwitch","where":[["_uuid","==",["uuid",db_uuid]]],"op":"select"},{"comment":"ovs-vsctl: ovs-vsctl -v --all destroy qos","op":"comment"}], "id":"1"}))
            s.close()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.host, self.port))

        print "whole queue is: %s" %result['result']['Queue']
        for queue_row in result['result']['Queue'].keys():
           s.send(json.dumps({"method":"transact", "params":["Open_vSwitch",{"table":"Queue","where":[["_uuid","==",["uuid",queue_row]]],"op":"delete"},{"mutations":[["next_cfg","+=",1]],"table":"Open_vSwitch","where":[["_uuid","==",["uuid", db_uuid]]],"op":"mutate"},{"columns":["next_cfg"],"table":"Open_vSwitch","where":[["_uuid","==",["uuid",db_uuid]]],"op":"select"},{"comment":"ovs-vsctl: ovs-vsctl -v --all destroy queue","op":"comment"}], "id":"1"}))
           s.close()
           s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           s.connect((self.host, self.port))

        return Response(status=200, body='clearing\n')

    def add_to_table(self, req, port_name, max_rate, min_rate, ip_addr, port):
        unique = True
        element_to_replace = -1
        i=0

        for id_element in array_id:
            if(id_element == port_name):
                element_to_replace=i
                unique = False
            i=i+1


        if unique:
            array_id.append(port_name)
            array_max_rate.append(max_rate)
            array_min_rate.append(min_rate)
            array_ip.append(ip_addr)
            array_port.append(port)

    def remove_from_table(self, req, port_name):
        i=0
        found = False
        for id_element in array_id:
            if(id_element == port_name):
                found = True
                break
            i=i+1

        if found:
            del array_id[i]
            del array_max_rate[i]
            del array_min_rate[i]
            del array_ip[i]
            del array_port[i]


    def set(self, req, port_name, max_rate, min_rate, ip_addr, port):
        self.port_name = port_name
        self.max_rate = int(max_rate)
        self.min_rate = int(min_rate)
        self.host = ip_addr
        self.port = int(port)

        self.add_to_table(req, port_name, max_rate, min_rate, ip_addr, port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))

        s.send(json.dumps({"method":"monitor", "params":["Open_vSwitch",None,{"Port":{"columns":["name"]},"Open_vSwitch":{"columns":["cur_cfg"]}}], "id":"0"}))
        result = json.loads(s.recv(32768))
        print "port req <========\n%s\n\n" % str(result)
        db_uuid = result['result']['Open_vSwitch'].keys()[0]
        print "db uuid is %s" % db_uuid

        found = 0
        i = 0
        for port in result['result']['Port'].values():
            if(port['new']['name'] == self.port_name):
               port_uuid = result['result']['Port'].keys()[i]
               found = 1
            i=i+1
        if found:
            print "port uuid \n%s\n\n" %port_uuid
        else:
            print "port not found !!!"

        s.send(json.dumps({ "method":"transact", "params":["Open_vSwitch",{"row":{"type":"linux-htb"},"table":"QoS","op":"insert"},{"mutations":[["next_cfg","+=",1]],"table":"Open_vSwitch","where":[["_uuid","==",["uuid",db_uuid]]],"op":"mutate"},{"columns":["next_cfg"],"table":"Open_vSwitch","where":[["_uuid","==",["uuid",db_uuid]]],"op":"select"},{"comment":"ovs-vsctl: ovs-vsctl -v create qos type=linux-htb","op":"comment"}], "id":"1"}))
        result = json.loads(s.recv(32768))
        print "qos req <========\n%s\n\n" % str(result)
        qos_uuid = result['result'][0]['uuid'][1]
        print "qos uuid is %s" % qos_uuid

        s.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))

        s.send(json.dumps({"method":"transact", "params":["Open_vSwitch",{"row":{"other_config":["map",[["max-rate",str(self.max_rate)],["min-rate",str(self.min_rate)]]]},"table":"Queue","op":"insert"},{"mutations":[["next_cfg","+=",1]],"table":"Open_vSwitch","where":[["_uuid","==",["uuid",db_uuid]]],"op":"mutate"},{"columns":["next_cfg"],"table":"Open_vSwitch","where":[["_uuid","==",["uuid", db_uuid]]],"op":"select"},{"comment":"ovs-vsctl: ovs-vsctl -v create queue other-config:min-rate=2000000 other-config:max-rate=2000000","op":"comment"}], "id":"1"}))

        result = json.loads(s.recv(4096))
        print "queue req <========\n%s\n\n" % str(result)
        queue_uuid = result['result'][0]['uuid'][1]
        print "queue uuid is %s" % queue_uuid

        s.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))

        s.send(json.dumps({"method":"transact", "params":["Open_vSwitch",{"row":{"qos":["uuid",qos_uuid]},"table":"Port","where":[["_uuid","==",["uuid",port_uuid]]],"op":"update"},{"mutations":[["next_cfg","+=",1]],"table":"Open_vSwitch","where":[["_uuid","==",["uuid",db_uuid]]],"op":"mutate"},{"columns":["next_cfg"],"table":"Open_vSwitch","where":[["_uuid","==",["uuid",db_uuid]]],"op":"select"},{"comment":"ovs-vsctl: ovs-vsctl -v set port p1 qos=812aeb83-75b2-4627-ba6f-acf127044abf","op":"comment"}], "id":"1"}))

        result = json.loads(s.recv(4096))
        print "port set req <========\n%s\n\n" % str(result)

        s.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))



        s.send(json.dumps({"method":"transact", "params":["Open_vSwitch",{"row":{"queues":["map",[[0,["uuid",queue_uuid]]]]},"table":"QoS","where":[["_uuid","==",["uuid",qos_uuid]]],"op":"update"},{"mutations":[["next_cfg","+=",1]],"table":"Open_vSwitch","where":[["_uuid","==",["uuid",db_uuid]]],"op":"mutate"},{"columns":["next_cfg"],"table":"Open_vSwitch","where":[["_uuid","==",["uuid",db_uuid]]],"op":"select"},{"comment":"ovs-vsctl: ovs-vsctl -v set qos 11f531d1-6b08-4852-986a-22f1b20e6fc7 queues=0=15970f0e-e143-4078-9460-47ddf69cb11a","op":"comment"}], "id":"1"}))

        result = json.loads(s.recv(4096))
        print "qos set req <========\n%s\n\n" % str(result)

        s.close()

        return Response(status=200, body='setting\n')

    def remove(self, req, port_name):
        self.clear(req, port_name)
        self.remove_from_table(req, port_name)

    def migrate_reconnect(self, req, port_name, ip_addr, port):
        i=0
        found = False
        for id_element in array_id:
            if(id_element == port_name):
                found = True
                array_ip[i] = ip_addr
                array_port[i] = port
                break
            i=i+1

        if found:
            return self.set(req, array_id[i], array_max_rate[i], array_min_rate[i], ip_addr, port)
        else:
            print "QoS settings not found, reset them"
            return Response(status=200, body='failed reconnect\n')

class restapi(app_manager.RyuApp):
    _CONTEXTS = {
        'network': network.Network,
        'wsgi': WSGIApplication
        }

    def __init__(self, *args, **kwargs):
        super(restapi, self).__init__(*args, **kwargs)
        self.nw = kwargs['network']
        wsgi = kwargs['wsgi']
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

        # For QoS
        wsgi.registory['QoSController'] = None
        uri = '/v1.0/qos/test/{port_name}/{max_rate}/{min_rate}'
        mapper.connect('qos', uri,
                        controller=QoSController, action='test',
                        conditions=dict(method=['GET']))

        uri = '/v1.0/qos/set/{port_name}/{max_rate}/{min_rate}/{ip_addr}/{port}'
        mapper.connect('qos', uri,
                        controller=QoSController, action='set',
                        conditions=dict(method=['GET']))

        uri = '/v1.0/qos/remove/{port_name}'
        mapper.connect('qos', uri,
                        controller=QoSController, action='remove',
                        conditions=dict(method=['GET']))

        uri = '/v1.0/qos/migrate/{port_name}'
        mapper.connect('qos', uri,
                        controller=QoSController, action='clear',
                        conditions=dict(method=['GET']))

        uri = '/v1.0/qos/migrate_reconnect/{port_name}/{ip_addr}/{port}'
        mapper.connect('qos', uri,
                        controller=QoSController, action='migrate_reconnect',
                        conditions=dict(method=['GET']))
