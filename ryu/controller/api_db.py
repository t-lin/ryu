# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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

import logging
import gflags
import migrate.changeset

from ryu.exception import NetworkNotFound, NetworkAlreadyExist
from ryu.exception import PortAlreadyExist, PortNotFound
from ryu.exception import MacAddressDuplicated, MacAddressNotFound
from ryu.exception import BondPortAlreadyBonded, BondAlreadyExist, BondPortNotFound, BondNotFound
from ryu.exception import FlowSpaceIDAlreadyExist, NetworkAlreadyAssigned
from ryu.app.rest_nw_id import NW_ID_EXTERNAL
from sqlalchemy.ext.sqlsoup import SqlSoup
from sqlalchemy import create_engine, MetaData
from sqlalchemy import Table, Column, Integer, String
from sqlalchemy import and_
import sqlalchemy.exc as sqlexc

LOG = logging.getLogger('ryu.controller.api_db')

FLAGS = gflags.FLAGS
gflags.DEFINE_string('api_db_url', 'mysql://root:iheartdatabases@'+ \
                        'localhost/ryu?charset=utf8', 'Ryu Database URL')

# Save API calls that may affect the state of the controller
# Can be re-loaded if controller crashes
class API_DB(object):
    def __init__(self):
        # Create any tables that don't already exist
        self.createTables()

        self.db = SqlSoup(FLAGS.api_db_url)
        self.db_nets = self.db.networks
        self.db_ports = self.db.ports
        self.db_macs = self.db.macs
        self.db_bonds = self.db.bonds
        self.db_flowspace = self.db.flowspace
        self.db_net2slice = self.db.delegated_nets

    def createTables(self):
        engine = create_engine(FLAGS.api_db_url)
        data = MetaData(bind=engine)
        data.reflect()
        existing_tables = data.tables.keys()

        # Dictionary for database description
        # Format: {Table object /w primary Column: [list of extra Column objects]}
        db_schema = {
            Table('networks', data,
                    Column('network_id', String(255), primary_key=True), keep_existing=True) :
                [],

            Table('ports', data,
                    Column('id', Integer, primary_key=True, autoincrement=True), keep_existing=True) :
                [   Column('port_num', Integer),
                    Column('datapath_id', String(255)),
                    Column('network_id', String(255)),
                    Column('bond_id', String(255))  ],

            Table('macs', data,
                    Column('mac_address', String(255), primary_key=True), keep_existing=True) :
                [   Column('network_id', String(255))   ],

            Table('bonds', data,
                    Column('bond_id', String(255), primary_key=True), keep_existing=True) :
                [   Column('datapath_id', String(255)),
                    Column('network_id', String(255))   ],

            Table('flowspace', data,
                    Column('id', Integer, primary_key=True), keep_existing=True) :
                [   Column('datapath_id', String(255)),
                    Column('port_num', Integer),
                    Column('mac_address', String(255))  ],

            Table('delegated_nets', data,
                    Column('network_id', String(255), primary_key=True), keep_existing=True) :
                [   Column('slice', String(255))    ],
        }

        for tab, colList in db_schema.items():
            # Create table if it doesn't exist
            if tab.name not in existing_tables:
                tab.create()

            # Check columns and update if necessary
            for col in colList:
                if col.name not in tab.c.keys():
                    col.create(tab, populate_default=True)

    def checkConnection(self):
        try:
            # Do a simple query
            self.db.execute("show databases")
        except sqlexc.OperationalError:
            # Connection was interrupted for some reason, try restarting session
            self.db.session.close()
            self.db.session.rollback()

            # Try simple query again
            self.db.execute("show databases")
        except:
            # Unknown exception, raise
            raise

    ###########################################################################
    # Functions for retrieving database contents
    ###########################################################################
    def getNetworks(self):
        self.checkConnection()
        net_list = []
        for net in self.db_nets.all():
            net_list.append(net.network_id)

        return net_list

    def getPorts(self):
        self.checkConnection()
        port_list = []
        for port in self.db_ports.all():
            port_list.append((port.network_id, port.datapath_id, port.port_num, port.bond_id))

        return port_list

    def getMACs(self):
        self.checkConnection()
        mac_list = []
        for mac in self.db_macs.all():
            mac_list.append((mac.network_id, mac.mac_address))

        return mac_list

    def getBonds(self):
        self.checkConnection()
        bond_list = []
        for bond in self.db_bonds.all():
            bond_list.append((bond.bond_id, bond.datapath_id, bond.network_id))

        return bond_list

    def getFlowSpace(self):
        self.checkConnection()
        flowspace_list = []
        for flowspace in self.db_flowspace.all():
            flowspace_list.append((flowspace.id, flowspace.datapath_id, flowspace.port_num, flowspace.mac_address))

        return flowspace_list

    def getDelegatedNets(self):
        self.checkConnection()
        net2slice_list = []
        for net2slice in self.db_net2slice.all():
            net2slice_list.append((net2slice.network_id, net2slice.slice))

        return net2slice_list

    ###########################################################################
    # Functions for storing API calls into the database
    ###########################################################################
    def createNetwork(self, network_id, update=False):
        self.checkConnection()
        if not self.db_nets.get(network_id):
            self.db_nets.insert(network_id=network_id)
        else:
            if not update:
                raise NetworkAlreadyExist(network_id=network_id)

        self.db.commit()

    def updateNetwork(self, network_id):
        self.createNetwork(network_id, True)

    def deleteNetwork(self, network_id):
        self.checkConnection()
        entry = self.db_nets.get(network_id)
        if entry:
            self.db.delete(entry)
        else:
            raise NetworkNotFound(network_id=network_id)

        self.db.commit()

    def addMAC(self, network_id, mac):
        self.checkConnection()
        entry = self.db_macs.get(mac)
        # Check for existing entry
        if not entry:
            self.db_macs.insert(network_id=network_id, mac_address=mac)
        else:
            if entry.network_id == network_id or network_id == NW_ID_EXTERNAL:
                # If old network and new network the same, do nothing
                # Or if trying to change an existing net association to NW_ID_EXTERNAL, do nothing
                self.db.rollback()
                return
            elif entry.network_id == NW_ID_EXTERNAL:
                # Allow changing from NW_ID_EXTERNAL to a known network UUID
                entry.network_id = network_id
            else:
                raise MacAddressDuplicated(mac=mac)

        try:
            self.db.commit()
        except sqlexc.IntegrityError:
            # Most likely due to race condition between setting DB change
            # and packet arriving at next switch triggering a DB read
            self.db.session.rollback()

    def delMAC(self, mac):
        self.checkConnection()
        entry = self.db_macs.get(mac)
        if entry:
            self.db.delete(entry)
        else:
            raise MacAddressNotFound(mac=mac)

        self.db.commit()

    def createPort(self, network_id, dpid, port_num, update=False):
        self.checkConnection()
        # Check for existing entry
        dpid = dpid.lstrip('0')
        params = and_(self.db_ports.datapath_id==dpid,
                        self.db_ports.port_num==port_num)
        old_entry = self.db_ports.filter(params).first()

        if not old_entry:
            # If updating but didn't locate existing entry, raise exception?
            # For now, just insert the entry and return success
            self.db_ports.insert(network_id=network_id,
                                    datapath_id=dpid, port_num=port_num)
        else:
            if update:
                old_entry.network_id = network_id
            else:
                # Entry already exists for (dpid,port) <=> network
                raise PortAlreadyExist(network_id=network_id,
                                        dpid=dpid, port=port_num)

        self.db.commit()

    def updatePort(self, network_id, dpid, port_num):
        self.createPort(network_id, dpid, port_num, True)

    def deletePort(self, network_id, dpid, port_num):
        self.checkConnection()
        dpid = dpid.lstrip('0')
        params = and_(self.db_ports.datapath_id==dpid,
                        self.db_ports.port_num==port_num)
        entry = self.db_ports.filter(params).first()

        if entry:
            self.db.delete(entry)
        else:
            raise PortNotFound(network_id=network_id,
                                dpid=dpid, port=port_num)

        self.db.commit()

    def createBond(self, bond_id, dpid, network_id):
        self.checkConnection()
        # Check for existing entry
        dpid = dpid.lstrip('0')
        if not self.db_bonds.get(bond_id):
            self.db_bonds.insert(bond_id=bond_id, datapath_id=dpid, network_id=network_id)
        else:
            raise BondAlreadyExist(bond_id=bond_id)

        self.db.commit()

    def deleteBond(self, bond_id):
        self.checkConnection()
        entry = self.db_bonds.get(bond_id)

        if entry:
            self.db.delete(entry)
        else:
            # Do nothing
            pass

        # Delete any ports currently bonded to the bond_id
        for port in self.db_ports.all():
            if port.bond_id == bond_id:
                port.bond_id = None

        self.db.commit()

    def addPort_bond(self, bond_id, port_num):
        self.checkConnection()
        bondEntry = self.db_bonds.get(bond_id)
        if bondEntry:
            dpid = bondEntry.datapath_id
            network_id = bondEntry.network_id
        else:
            raise BondNotFound(bond_id=bond_id)

        params = and_(self.db_ports.datapath_id==dpid,
                        self.db_ports.network_id==network_id,
                        self.db_ports.port_num==port_num)
        entry = self.db_ports.filter(params).first()

        if entry:
            # Check for existing entry
            old_bond_id = entry.bond_id
            if not old_bond_id:
                entry.bond_id = bond_id
            else:
                raise BondPortAlreadyBonded(port=port_num, bond_id=old_bond_id)
        else:
            raise PortNotFound(network_id=network_id,
                                dpid=dpid, port=port_num)

        self.db.commit()

    def deletePort_bond(self, bond_id, port_num):
        self.checkConnection()
        bondEntry = self.db_bonds.get(bond_id)
        if bondEntry:
            dpid = bondEntry.datapath_id
        else:
            raise BondNotFound(bond_id=bond_id)

        params = and_(self.db_ports.datapath_id==dpid,
                        self.db_ports.port_num==port_num,
                        self.db_ports.bond_id==bond_id)
        entry = self.db_ports.filter(params).first()

        if entry:
            entry.bond_id = None
        else:
            raise BondPortNotFound(port=port_num, bond_id=bond_id)

        self.db.commit()

    def addFlowSpaceID(self, dpid, port_num, mac, id):
        self.checkConnection()
        entry = self.db_flowspace.get(id)
        if not entry:
            self.db_flowspace.insert(id=id, datapath_id=dpid, port_num=port_num, mac_address=mac)
        else:
            raise FlowSpaceIDAlreadyExist(flowspace_id=id)

        self.db.commit()

    def delFlowSpaceID(self, id):
        self.checkConnection()
        entry = self.db_flowspace.get(id)
        if entry:
            self.db.delete(entry)
        else:
            # Not found, raise exception?
            pass

        self.db.commit()

    def assignNetToSlice(self, sliceName, network_id):
        self.checkConnection()
        entry = self.db_net2slice.get(network_id)
        if not entry:
            self.db_net2slice.insert(network_id=network_id, slice=sliceName)
        else:
            raise NetworkAlreadyAssigned(network_id=network_id, sliceName=entry.slice)

        self.db.commit()

    def removeNetFromSlice(self, network_id):
        self.checkConnection()
        entry = self.db_net2slice.get(network_id)
        if entry:
            self.db.delete(entry)
        else:
            # Not found, raise exception?
            pass

        self.db.commit()


