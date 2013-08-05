# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
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
import struct

from ryu.app.rest_nw_id import NW_ID_UNKNOWN, NW_ID_EXTERNAL
from ryu.app.rest_nw_id import NW_ID_PXE_CTRL, NW_ID_PXE, NW_ID_MGMT_CTRL, NW_ID_MGMT
from ryu.base import app_manager
from ryu.exception import MacAddressDuplicated, MacAddressNotFound
from ryu.exception import PortUnknown
from ryu.controller import dpset
from ryu.controller import mac_to_network
from ryu.controller import mac_to_port
from ryu.controller import network
from ryu.controller import ofp_event
from ryu.controller import flowvisor_cli
from ryu.controller import port_bond
from ryu.controller import api_db
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import nx_match
from ryu.lib.mac import haddr_to_str
from ryu.lib import mac


LOG = logging.getLogger('ryu.app.simple_isolation')


class SimpleIsolation(app_manager.RyuApp):
    _CONTEXTS = {
        'network': network.Network,
        'dpset': dpset.DPSet,
        'fv_cli': flowvisor_cli.FlowVisor_CLI,
        'mac2port': mac_to_port.MacToPortTable,
        'mac2net': mac_to_network.MacToNetwork,
        'port_bond': port_bond.PortBond,
        'api_db': api_db.API_DB
    }

    def __init__(self, *args, **kwargs):
        super(SimpleIsolation, self).__init__(*args, **kwargs)
        self.nw = kwargs['network']
        self.dpset = kwargs['dpset']
        self.mac2port = kwargs['mac2port']
        self.mac2net = kwargs['mac2net']
        self.fv_cli = kwargs['fv_cli']
        self.port_bond = kwargs['port_bond']
        self.api_db = kwargs['api_db']

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        #if datapath.id == 0x80027513556:
        #   return

        datapath.send_delete_all_flows()
        datapath.send_barrier()

        self.mac2port.dpid_add(ev.msg.datapath_id)
        self.nw.add_datapath(ev.msg)

    def _install_modflow(self, msg, src, dst, actions, eth_type):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        if LOG.getEffectiveLevel() == logging.DEBUG:
            if len(actions) > 0:
                act = "out to "
                for action in actions:
                    act += str(action.port) + ","
            else:
                act = "drop"
            LOG.debug("installing flow from port %s, src %s to dst %s, action %s", msg.in_port, haddr_to_str(src), haddr_to_str(dst), act)
        if actions is None:
            actions = []

        # install flow
        rule = nx_match.ClsRule()
        rule.set_in_port(msg.in_port)
        if dst is not None:
            rule.set_dl_dst(dst)
        if eth_type is not None:
            rule.set_dl_type(eth_type)
        rule.set_dl_src(src)
        datapath.send_flow_mod(
            rule=rule, cookie=0, command=datapath.ofproto.OFPFC_ADD,
            idle_timeout=90, hard_timeout=90,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            buffer_id=0xffffffff, out_port=ofproto.OFPP_NONE,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

    # Creates the appropriate action lists and installs the flows
    # Returns the list of action(s) it installed
    def _install_unicast_flow(self, msg, src, dst, out_port, eth_type):
        datapath = msg.datapath

        in_bond_id = self.port_bond.get_bond_id(datapath.id, msg.in_port)
        out_bond_id = self.port_bond.get_bond_id(datapath.id, out_port)
        if in_bond_id == out_bond_id and (in_bond_id or out_bond_id):
            self._modflow_and_drop_packet(msg, src, dst)
            return []

        if out_bond_id:
            # Choose output port based on round-robin
            out_port = self.port_bond.get_out_port(out_bond_id)

            orig_in_port = msg.in_port
            # Prevent potential loopbacks if downstream ports not bonded in switch
            # Install a drop rule for each port in bond
            for port in self.port_bond.ports_in_bond(out_bond_id):
                msg.in_port = port
                self._install_modflow(msg, src, dst=None, actions=[], eth_type=eth_type)

            # Replace msg.in_port with original
            msg.in_port = orig_in_port

        if in_bond_id:
            orig_in_port = msg.in_port

            # Install flow for each input port in bond
            for port in self.port_bond.ports_in_bond(in_bond_id):
                msg.in_port = port
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                self._install_modflow(msg, src, dst=dst, actions=actions, eth_type=eth_type)

            # Replace msg.in_port with original
            msg.in_port = orig_in_port
        else:
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            self._install_modflow(msg, src, dst=dst, actions=actions, eth_type=eth_type)

        return actions

    def _forward_to_nw_id(self, msg, src, dst, nw_id, out_port, eth_type):
        assert out_port is not None
        datapath = msg.datapath

        if not self.nw.same_network(datapath.id, nw_id, out_port,
                                    NW_ID_EXTERNAL):
            LOG.debug('packet is blocked src %s dst %s '
                      'from %d to %d on datapath %d',
                      haddr_to_str(src), haddr_to_str(dst),
                      msg.in_port, out_port, datapath.id)
            return

        # Install unicast flows and retrieve resulting actions list
        actions = self._install_unicast_flow(msg, src, dst, out_port, eth_type)
        if actions:
            LOG.debug("learned dpid %s in_port %d out_port %d src %s dst %s",
                      datapath.id, msg.in_port, actions[0].port,
                      haddr_to_str(src), haddr_to_str(dst))

        datapath.send_packet_out(msg.buffer_id, msg.in_port, actions)

    # Given an input port, datapath ID, and network ID, return
    #   a list of valid output ports
    def _get_all_out_ports(self, dpid, in_port, nw_id, allow_other_nw_id=None):
        in_bond_id = self.port_bond.get_bond_id(dpid, in_port)
        # Retrieve all output ports regardless of bond
        out_port_list = set(self.nw.filter_ports(dpid, in_port, nw_id, allow_other_nw_id))

        # Remove all ports that belong in a bond
        bond_list = self.port_bond.list_bonds(dpid, nw_id)
        if allow_other_nw_id:
            bond_list.extend(self.port_bond.list_bonds(dpid, allow_other_nw_id))

        for bond_id in bond_list:
            bond_ports = set(self.port_bond.ports_in_bond(bond_id))
            out_port_list -= bond_ports

            # Re-add one port for each bond (Except source bond, if source port is bonded)
            if in_bond_id != bond_id:
                out_port = self.port_bond.get_out_port(bond_id)
                if out_port:
                    out_port_list.add(out_port)

        return list(out_port_list)

    def _flood_to_nw_id(self, msg, src, dst, nw_id, eth_type):
        LOG.info("flood to nw id %s", nw_id)
        datapath = msg.datapath
        in_port = msg.in_port
        actions = []
        LOG.debug("dpid %s in_port %d src %s dst %s ports %s",
                  datapath.id, msg.in_port,
                  haddr_to_str(src), haddr_to_str(dst),
                  self.nw.dpids.get(datapath.id, {}).items())

        out_port_list = self._get_all_out_ports(datapath.id, msg.in_port,
                                                    nw_id, NW_ID_EXTERNAL)
        LOG.debug("out port list %s", out_port_list)

        for port_no in out_port_list:
            LOG.debug("port_no %s", port_no)
            actions.append(datapath.ofproto_parser.OFPActionOutput(port_no))

            # Prevent potential loopbacks if downstream ports not bonded in switch
            out_bond_id = self.port_bond.get_bond_id(datapath.id, port_no)
            if out_bond_id:
                # Install a drop rule for each port in bond
                for port in self.port_bond.ports_in_bond(out_bond_id):
                    msg.in_port = port
                    self._install_modflow(msg, src, dst=None, actions=[], eth_type=eth_type)

                # Replace msg.in_port with original
                msg.in_port = in_port

        in_bond_id = self.port_bond.get_bond_id(datapath.id, in_port)
        if in_bond_id:
            # Install a flow for each port in bond
            for port in self.port_bond.ports_in_bond(in_bond_id):
                msg.in_port = port
                self._install_modflow(msg, src, dst, actions, eth_type)
        else:
            self._install_modflow(msg, src, dst, actions, eth_type)

        datapath.send_packet_out(msg.buffer_id, in_port, actions)
        LOG.info("sent out to these ports: %s", out_port_list)

    def _learned_mac_or_flood_to_nw_id(self, msg, src, dst,
                                       dst_nw_id, out_port, eth_type):
        if out_port is not None:
            self._forward_to_nw_id(msg, src, dst, dst_nw_id, out_port, eth_type)
        else:
            self._flood_to_nw_id(msg, src, dst, dst_nw_id, eth_type)

    def _modflow_and_drop_packet(self, msg, src, dst, eth_type):
        LOG.info("installing flow for dropping packet")
        datapath = msg.datapath
        in_port = msg.in_port

        bond_id = self.port_bond.get_bond_id(datapath.id, msg.in_port)
        if bond_id:
            for port in self.port_bond.ports_in_bond(bond_id):
                msg.in_port = port
                self._install_modflow(msg, src, dst, [], eth_type)
        else:
            self._install_modflow(msg, src, dst, [], eth_type)

        datapath.send_packet_out(msg.buffer_id, in_port, [])

    def _drop_packet(self, msg):
        datapath = msg.datapath
        LOG.debug("Dropping packet; Dpid: %s; In port: %s",
                    datapath.id, msg.in_port)
        datapath.send_packet_out(msg.buffer_id, msg.in_port, [])

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # LOG.debug('packet in ev %s msg %s', ev, ev.msg)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        
        #if datapath.id == 0x80027513556:
        #   return

        dst, src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)
        if self.nw.arp_enabled and _eth_type == 0x0806:
           #arp is not handled by this application
           LOG.info("main app: ignore arp (%s, %s)", hex(datapath.id), msg.in_port)
           return

        LOG.info("packet in from port %s of dpid %s", msg.in_port, hex(datapath.id))
        LOG.info("src mac %s, dst mac %s", haddr_to_str(src), haddr_to_str(dst))
        if _eth_type == 0x0800:
            temp1, temp2, temp3, src_ip, dst_ip = struct.unpack_from('!LLL4s4s', buffer(msg.data), 14)
            LOG.info("ip packet: src = %s, dst = %s", mac.ipaddr_to_str(src_ip), mac.ipaddr_to_str(dst_ip))

        try:
            port_nw_id = self.nw.get_network(datapath.id, msg.in_port)
        except PortUnknown:
            port_nw_id = NW_ID_UNKNOWN

        if port_nw_id != NW_ID_UNKNOWN:
            # Here it is assumed that the
            # (port <-> network id)/(mac <-> network id) relationship
            # is stable once the port is created. The port will be destroyed
            # before assigning new network id to the given port.
            # This is correct nova-network/nova-compute.
            try:
                # allow external -> known nw id change
                self.mac2net.add_mac(src, port_nw_id, NW_ID_EXTERNAL)
                self.api_db.addMAC(port_nw_id, haddr_to_str(src))
                if _eth_type == 0x0800 and (port_nw_id == NW_ID_PXE or port_nw_id == NW_ID_PXE_CTRL
                     or port_nw_id == NW_ID_MGMT or port_nw_id == NW_ID_MGMT_CTRL):  
                   #only IP packet for above networks
                   temp1, temp2, temp3, src_ip, dst_ip = struct.unpack_from('!LLL4s4s', buffer(msg.data), 14)
                   LOG.info("ip packet: src = %s, dst = %s", mac.ipaddr_to_str(src_ip), mac.ipaddr_to_str(dst_ip))
                   if "0.0.0.0" != mac.ipaddr_to_str(src_ip):
                      self.mac2port.port_add(datapath, msg.in_port, src, src_ip)
            except MacAddressDuplicated:
                LOG.warn('mac address %s is already in use.'
                         ' So (dpid %s, port %s) can not use it',
                         haddr_to_str(src), datapath.id, msg.in_port)
                #
                # should we install drop action pro-actively for future?
                #
                self._drop_packet(msg)
                return

        old_port = self.mac2port.port_add(datapath.id, msg.in_port, src)
        if old_port is not None and old_port != msg.in_port:
            # We really overwrite already learned mac address.
            # So discard already installed stale flow entry which conflicts
            # new port.
            rule = nx_match.ClsRule()
            rule.set_dl_dst(src)
            rule.set_dl_type(_eth_type)
            datapath.send_flow_mod(rule=rule,
                                   cookie=0,
                                   command=ofproto.OFPFC_DELETE,
                                   idle_timeout=0,
                                   hard_timeout=0,
                                   priority=ofproto.OFP_DEFAULT_PRIORITY,
                                   out_port=old_port)

            # to make sure the old flow entries are purged.
            datapath.send_barrier()

        src_nw_id = self.mac2net.get_network(src, NW_ID_UNKNOWN)
        dst_nw_id = self.mac2net.get_network(dst, NW_ID_UNKNOWN)

        # If (input port belongs to a delegated network):
        #    Add FlowSpace for (dpid, port, src_mac)
        #    Drop current packet
        # Else if ((port is an external) AND (src_mac belongs to a delegated network)):
        #    Add FlowSpace for (dpid, port, src_mac)
        #    Drop current packet
        port_sliceName = self.fv_cli.getSliceName(port_nw_id)
        src_sliceName = self.fv_cli.getSliceName(src_nw_id)
        if port_sliceName or \
           ((port_nw_id == NW_ID_EXTERNAL) and src_sliceName):
            sliceName = port_sliceName or src_sliceName

            # Add FV rules if the target slice is not the default slice and if
            #    there currently exists no rules matching (dpid, port, mac).
            #    The second condition avoids installing duplicate rules if subsequent
            #    packets are queued in Ryu before rule installation triggered
            #    from first packet is completed
            if (sliceName != self.fv_cli.defaultSlice) and \
               (len(self.fv_cli.getFlowSpaceIDs(datapath.id, msg.in_port, src)) == 0):
                # ORDER OF INSTALLING RULES IS IMPORTANT! Install rules for other switches
                #   before installing rules for source switch. This avoids subsequent
                #   packets from reaching non-source switches before rules can be properly
                #   installed on them, which will trigger duplicate rules to be isntalled.
                # Need to install mac for all EXTERNAL ports throughout network
                for (dpid, port) in self.nw.list_ports(NW_ID_EXTERNAL):
                    if (dpid == datapath.id):
                        continue

                    ret = self.fv_cli.addFlowSpace(sliceName, dpid, port, haddr_to_str(src))
                    if (ret.find("success") == -1):
                        # Error, how to handle?
                        LOG.debug("Error while installing FlowSpace for slice %s: (%s, %s, %s)",\
                                    sliceName, dpid, str(port), haddr_to_str(src))
                    else:
                        self.fv_cli.addFlowSpaceID(dpid, port, src, int(ret[9:]))
                        self.api_db.addFlowSpaceID(hex(dpid), port, haddr_to_str(src), int(ret[9:]))

                # Now install rule on source switch
                ret = self.fv_cli.addFlowSpace(sliceName, datapath.id, msg.in_port, haddr_to_str(src))
                if (ret.find("success") == -1):
                    # Error, how to handle?
                    LOG.debug("Error while installing FlowSpace for slice %s: (%s, %s, %s)",\
                                sliceName, dpid, str(port), haddr_to_str(src))
                else:
                    self.fv_cli.addFlowSpaceID(datapath.id, msg.in_port, src, int(ret[9:]))
                    self.api_db.addFlowSpaceID(hex(datapath.id), msg.in_port, haddr_to_str(src), int(ret[9:]))

            self._drop_packet(msg)
            return

        # we handle multicast packet as same as broadcast
        broadcast = (dst == mac.BROADCAST) or mac.is_multicast(dst)
        out_port = self.mac2port.port_get(datapath.id, dst)

        if src_nw_id == NW_ID_PXE or src_nw_id == NW_ID_PXE_CTRL:
            self.pktHandling_PXE(msg, datapath, ofproto, dst, src, broadcast,
                                    port_nw_id, src_nw_id, dst_nw_id, out_port, _eth_type)
        elif src_nw_id == NW_ID_MGMT or src_nw_id == NW_ID_MGMT_CTRL:
            self.pktHandling_MGMT(msg, datapath, ofproto, dst, src, broadcast,
                                    port_nw_id, src_nw_id, dst_nw_id, out_port, _eth_type)
        else:
            self.pktHandling_BaseCase(msg, datapath, ofproto, dst, src, broadcast,
                                        port_nw_id, src_nw_id, dst_nw_id, out_port, _eth_type)
        LOG.info("\n")

    def _port_add(self, ev):
        #
        # delete flows entries that matches with
        # dl_dst == broadcast/multicast
        # and dl_src = network id if network id of this port is known
        # to send broadcast packet to this newly added port.
        #
        # Openflow v1.0 doesn't support masked match of dl_dst,
        # so delete all flow entries. It's inefficient, though.
        #
        msg = ev.msg
        datapath = msg.datapath

        datapath.send_delete_all_flows()
        datapath.send_barrier()
        self.nw.port_added(datapath, msg.desc.port_no)

    def _port_del(self, ev):
        # free mac addresses associated to this VM port,
        # and delete related flow entries for later reuse of mac address

        dps_needs_barrier = set()

        msg = ev.msg
        datapath = msg.datapath
        datapath_id = datapath.id
        port_no = msg.desc.port_no

        rule = nx_match.ClsRule()
        rule.set_in_port(port_no)
        datapath.send_flow_del(rule=rule, cookie=0)

        rule = nx_match.ClsRule()
        datapath.send_flow_del(rule=rule, cookie=0, out_port=port_no)
        dps_needs_barrier.add(datapath)

        try:
            port_nw_id = self.nw.get_network(datapath_id, port_no)
        except PortUnknown:
            # race condition between rest api delete port
            # and openflow port deletion ofp_event
            pass
        else:
            if port_nw_id in (NW_ID_UNKNOWN, NW_ID_EXTERNAL):
                datapath.send_barrier()
                return

        for mac_ in self.mac2port.mac_list(datapath_id, port_no):
            for (_dpid, dp) in self.dpset.get_all():
                if self.mac2port.port_get(dp.id, mac_) is None:
                    continue

                rule = nx_match.ClsRule()
                rule.set_dl_src(mac_)
                dp.send_flow_del(rule=rule, cookie=0)

                rule = nx_match.ClsRule()
                rule.set_dl_dst(mac_)
                dp.send_flow_del(rule=rule, cookie=0)
                dps_needs_barrier.add(dp)

                self.mac2port.mac_del(dp.id, mac_)

            try:
                self.mac2net.del_mac(mac_)
                self.api_db.delMAC(haddr_to_str(mac_))
            except MacAddressNotFound:
                # Race condition between del_mac REST API and OF port_del ofp_event
                # Other possibility is that Ryu has been restarted after a crash
                pass

        self.nw.port_deleted(datapath.id, port_no)

        for dp in dps_needs_barrier:
            dp.send_barrier()

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        ofproto = msg.datapath.ofproto

        #if msg.datapath.id == 0x80027513556:
        #   return

        if reason == ofproto.OFPPR_ADD:
            self._port_add(ev)
        elif reason == ofproto.OFPPR_DELETE:
            self._port_del(ev)
        else:
            assert reason == ofproto.OFPPR_MODIFY

    # ===========================================================
    # Packet handling logic functions
    # ===========================================================

    def pktHandling_BaseCase(self, msg, datapath, ofproto, dst, src, broadcast,
                                    port_nw_id, src_nw_id, dst_nw_id, out_port, eth_type):
        #
        # there are several combinations:
        # in_port: known nw_id, external, unknown nw,
        # src mac: known nw_id, external, unknown nw,
        # dst mac: known nw_id, external, unknown nw, and broadcast/multicast
        # where known nw_id: is quantum network id
        #       external: means that these ports are connected to outside
        #       unknown nw: means that we don't know this port is bounded to
        #                   specific nw_id or external
        #       broadcast: the destination mac address is broadcast address
        #                  (or multicast address)
        #
        # Can the following logic be refined/shortened?
        #

        # When NW_ID_UNKNOWN is found, registering ports might be delayed.
        # So just drop only this packet and not install flow entry.
        # It is expected that when next packet arrives, the port is registers
        # with some network id

        if port_nw_id != NW_ID_EXTERNAL and port_nw_id != NW_ID_UNKNOWN:
            if broadcast:
                # flood to all ports of external or src_nw_id
                self._flood_to_nw_id(msg, src, dst, src_nw_id, eth_type)
            elif src_nw_id == NW_ID_EXTERNAL:
                self._modflow_and_drop_packet(msg, src, dst, eth_type)
                return
            elif src_nw_id == NW_ID_UNKNOWN:
                self._drop_packet(msg)
                return
            else:
                # src_nw_id != NW_ID_EXTERNAL and src_nw_id != NW_ID_UNKNOWN:
                #
                # try learned mac check if the port is net_id
                # or
                # flood to all ports of external or src_nw_id
                self._learned_mac_or_flood_to_nw_id(msg, src, dst,
                                                    src_nw_id, out_port, eth_type)

        elif port_nw_id == NW_ID_EXTERNAL:
            if src_nw_id != NW_ID_EXTERNAL and src_nw_id != NW_ID_UNKNOWN:
                if broadcast:
                    # flood to all ports of external or src_nw_id
                    self._flood_to_nw_id(msg, src, dst, src_nw_id, eth_type)
                elif (dst_nw_id != NW_ID_EXTERNAL and
                      dst_nw_id != NW_ID_UNKNOWN):
                    if src_nw_id == dst_nw_id:
                        # try learned mac
                        # check if the port is external or same net_id
                        # or
                        # flood to all ports of external or src_nw_id
                        self._learned_mac_or_flood_to_nw_id(msg, src, dst,
                                                            src_nw_id,
                                                            out_port, eth_type)
                    else:
                        # should not occur?
                        LOG.debug("should this case happen?")
                        self._drop_packet(msg)
                elif dst_nw_id == NW_ID_EXTERNAL:
                    # try learned mac
                    # or
                    # flood to all ports of external or src_nw_id
                    self._learned_mac_or_flood_to_nw_id(msg, src, dst,
                                                        src_nw_id, out_port, eth_type)
                else:
                    assert dst_nw_id == NW_ID_UNKNOWN
                    LOG.debug("Unknown dst_nw_id")
                    self._drop_packet(msg)
            elif src_nw_id == NW_ID_EXTERNAL:
                self._modflow_and_drop_packet(msg, src, dst, eth_type)
            else:
                # should not occur?
                assert src_nw_id == NW_ID_UNKNOWN
                self._drop_packet(msg)
        else:
            # drop packets
            assert port_nw_id == NW_ID_UNKNOWN
            self._drop_packet(msg)
            # LOG.debug("Unknown port_nw_id")

    def pktHandling_PXE(self, msg, datapath, ofproto, dst, src, broadcast,
                                port_nw_id, src_nw_id, dst_nw_id, out_port, eth_type):
        # Isolate between controller and each BM servers

        in_port = msg.in_port
        in_bond_id = self.port_bond.get_bond_id(datapath.id, msg.in_port)
        out_bond_id = self.port_bond.get_bond_id(datapath.id, out_port)
        if in_bond_id:
            in_bond_ports = self.port_bond.ports_in_bond(in_bond_id)

        actions = []
        if broadcast or out_port is None:
            out_port_list = self._get_all_out_ports(datapath.id, in_port, NW_ID_PXE_CTRL)

            if src_nw_id == NW_ID_PXE_CTRL:
                out_port_list.extend(self._get_all_out_ports(datapath.id, in_port, NW_ID_PXE))

            for port in out_port_list:
                actions.append(datapath.ofproto_parser.OFPActionOutput(port))

            if broadcast:
                # If broadcasting, write mod flow into switch
                if in_bond_id:
                    for port in self.port_bond.ports_in_bond(in_bond_id):
                        msg.in_port = port
                        self._install_modflow(msg, src, dst, actions, eth_type)
                else:
                    self._install_modflow(msg, src, dst, actions, eth_type)
        else:
            # Check if output port is allowed (if source is PXE_CTRL network, don't care)
            if src_nw_id == NW_ID_PXE_CTRL or src_nw_id != dst_nw_id:
                # Install unicast flows and retrieve resulting actions list
                actions = self._install_unicast_flow(msg, src, dst, out_port, eth_type)
            else:
                # Installs rule to drop if actions list is empty
                self._install_modflow(msg, src, dst, actions, eth_type)

        datapath.send_packet_out(msg.buffer_id, in_port, actions)

    def pktHandling_MGMT(self, msg, datapath, ofproto, dst, src, broadcast,
                                port_nw_id, src_nw_id, dst_nw_id, out_port, eth_type):
        actions = []
        if broadcast or out_port is None:
            out_port_list = []
            out_port_list.extend(self.nw.filter_ports(datapath.id,
                                        msg.in_port, NW_ID_MGMT_CTRL))

            if src_nw_id == NW_ID_MGMT_CTRL:
                out_port_list.extend(self.nw.filter_ports(datapath.id,
                                                msg.in_port, NW_ID_MGMT))

            for port in out_port_list:
                actions.append(datapath.ofproto_parser.OFPActionOutput(port))

            if broadcast:
                # If broadcasting, write mod flow into switch
                self._install_modflow(msg, src, dst, actions, eth_type)
                datapath.send_packet_out(msg.buffer_id, msg.in_port, actions)
            else:
                # Simply flooding; Don't bother with mod flow
                datapath.send_packet_out(msg.buffer_id, msg.in_port, actions)
        else:
            # Check if output port is allowed (if source is MGMT_CTRL network, don't care)
            if src_nw_id == NW_ID_MGMT_CTRL or src_nw_id != dst_nw_id:
                actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))

            # Installs rule to drop if actions list is empty
            self._install_modflow(msg, src, dst, actions, eth_type)
            datapath.send_packet_out(msg.buffer_id, msg.in_port, actions)


