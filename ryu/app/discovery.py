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

import dpkt
import gevent
import gflags
import logging
import struct
import time
import uuid
from collections import deque
from dpkt.ethernet import Ethernet


from ryu import exception as ryu_exc
from ryu.base import app_manager
from ryu.controller import (dpset,
                            handler,
                            link_set,
                            ofp_event,
                            mac_to_port)
from ryu.controller.link_set import (Link,
                                     LinkSet)
from ryu.lib import (linked_dict,
                     lldp,
                     mac)
from ryu.lib.dpid import (dpid_to_str,
                          str_to_dpid)
from ryu.lib.lldp import (ChassisID,
                          End,
                          LLDP,
                          PortID,
                          TTL,
                          SystemName)
from ryu.ofproto import nx_match

import OFSniff # Lib for sniffing OF connection to calculate RTTs


LOG = logging.getLogger(__name__)


FLAGS = gflags.FLAGS
gflags.DEFINE_multistring('discovery_install_flow', True,
                          'disocvery: explicitly install flow entry '
                          'to send lldp packet to controller')
gflags.DEFINE_multistring('discovery_explicit_drop', True,
                          'disocvery: explicitly drop lldp packet in')


def port_is_down(dp, port):
    return bool((port.config & dp.ofproto.OFPPC_PORT_DOWN) |
                (port.state & dp.ofproto.OFPPS_LINK_DOWN))


class PortData(object):
    def __init__(self, is_down, data):
        super(PortData, self).__init__()
        self.is_down = is_down
        self.data = data # The serialized LLDP packet
        self.timestamp = None
        self.sent = 0

    def lldp_sent(self):
        self.timestamp = time.time()
        self.sent += 1

    def lldp_received(self):
        self.sent = 0

    def lldp_dropped(self):
        return self.sent

    def clear_timestamp(self):
        self.timestamp = None

    def set_down(self, is_down):
        self.is_down = is_down

    def __str__(self):
        return 'PortData<%s, %s, %d>' % (self.is_down,
                                         self.timestamp,
                                         self.sent)


class PortSet(object):
    def __init__(self):
        super(PortSet, self).__init__()

        # key (dp, port_no) -> data: PortData
        self._ports = linked_dict.LinkedDict()

    def add_port(self, dp, port_no, is_down, data):
        key = (dp, port_no)
        if key not in self._ports:
            self._ports.prepend(key, PortData(is_down, data))
        else:
            self._ports[key].is_down = is_down

    def lldp_sent(self, dp, port_no):
        key = (dp, port_no)
        port_data = self._ports[key]
        port_data.lldp_sent()
        self._ports.move_key_last(key)
        return port_data

    def lldp_received(self, dp, port_no):
        key = (dp, port_no)
        self._ports[key].lldp_received()

    def move_front(self, dp, port_no):
        key = (dp, port_no)
        port_data = self._ports.get(key, None)
        if port_data is not None:
            port_data.clear_timestamp()
            self._ports.move_key_front(key)

    def set_down(self, dp, port_no, is_down):
        key = (dp, port_no)
        port_data = self._ports[key]
        port_data.set_down(is_down)
        port_data.clear_timestamp()
        if not is_down:
            self._ports.move_key_front(key)

    def get_port(self, dp, port_no):
        key = (dp, port_no)
        return self._ports[key]

    def del_port(self, dp, port_no):
        key = (dp, port_no)
        del self._ports[key]

    def get_dp_port(self, dp):
        return [key_port_no for (key_dp, key_port_no) in self._ports
                if key_dp == dp]

    def items(self):
        return self._ports.items()


class LLDPPacket(object):
    CHASSIS_ID_PREFIX = 'dpid:'
    CHASSIS_ID_PREFIX_LEN = len(CHASSIS_ID_PREFIX)
    CHASSIS_ID_FMT = CHASSIS_ID_PREFIX + '%s'

    PORT_ID_STR = '!I'      # uint32_t
    PORT_ID_SIZE = 4

    # System name format: <sys name prefix>;<16-Byte Pkt ID>;<ctrl2switch RTT>
    SYSTEM_NAME_PREFIX = "SAVI-SDN"
    PKT_ID_START_IDX = 60 # Found from manual peeking
                          # Is there a way to dynamically calculate this?
    PKT_ID_LEN = len(uuid.uuid4().hex) # 32
    RTT_START_IDX = PKT_ID_START_IDX + PKT_ID_LEN + 1
    RTT_LEN = len("%17.6lf" % time.time()) # 17; Will this ever change?

    # Updates rtt in System Name TLV
    # Input: Serialized packet as a string
    # Returns a tuple: (updated serialized packet, ctrl <=> switch RTT)
    @staticmethod
    def update_rtt(eth_str, rtt):
        if rtt == 0:
            return (eth_str, rtt)

        # If rtt length changes, change the class' consts above
        rttString = "%17.6lf" % rtt

        # Really terrible to be doing this in Python... Slice string and re-create packet
        pktBeginning = eth_str[:LLDPPacket.RTT_START_IDX]
        pktEnding = eth_str[LLDPPacket.RTT_START_IDX + LLDPPacket.RTT_LEN:]

        new_eth_str = pktBeginning + rttString + pktEnding

        return (new_eth_str, rttString)

    # Updates packet's ID in System Name TLV
    # Input: Serialized packet as a string
    # Returns a tuple: (updated serialized packet, the packet ID)
    @staticmethod
    def update_packet_id(eth_str):
        # If UUID length changes, change the class' consts above
        packetID = uuid.uuid4().hex

        # Really terrible to be doing this in Python... Slice string and re-create packet
        pktBeginning = eth_str[:LLDPPacket.PKT_ID_START_IDX]
        pktEnding = eth_str[LLDPPacket.PKT_ID_START_IDX + LLDPPacket.PKT_ID_LEN:]

        new_eth_str = pktBeginning + packetID + pktEnding

        return (new_eth_str, packetID)

    @staticmethod
    def lldp_packet(dpid, port_no, dl_addr, ttl):
        tlv_chassis_id = ChassisID(subtype=ChassisID.SUB_LOCALLY_ASSIGNED,
                                   chassis_id=LLDPPacket.CHASSIS_ID_FMT %
                                   dpid_to_str(dpid))

        tlv_port_id = PortID(subtype=PortID.SUB_PORT_COMPONENT,
                             port_id=struct.pack(LLDPPacket.PORT_ID_STR,
                                                 port_no))

        tlv_ttl = TTL(ttl=ttl)

        # System name format: <sys name prefix>;<16-Byte Pkt ID>;<ctrl2switch RTT>
        # Fill system_name w/ dummy values for proper packet creation, will be replaced later
        tlv_name = SystemName()
        tlv_name.system_name = "%s;%s;%s" % (LLDPPacket.SYSTEM_NAME_PREFIX,\
                                                '0' * LLDPPacket.PKT_ID_LEN,\
                                                '0' * LLDPPacket.RTT_LEN)

        tlv_end = End()

        tlvs = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_name, tlv_end)
        lldp_data = LLDP(tlvs=tlvs)

        eth = Ethernet(dst=lldp.LLDP_MAC_NEAREST_BRIDGE, src=dl_addr,
                       type=lldp.ETH_TYPE_LLDP, data=lldp_data)
        return str(eth)         # serialize it

    class LLDPUnknownFormat(ryu_exc.RyuException):
        message = '%(msg)s'

    class NotLLDP(ryu_exc.RyuException):
        message = '%(msg)s'

    @staticmethod
    def lldp_parse(data):
        eth = Ethernet(data)
        if not (eth.dst == lldp.LLDP_MAC_NEAREST_BRIDGE and
                eth.type == lldp.ETH_TYPE_LLDP):
            raise LLDPPacket.NotLLDP(
                msg='unknown dst mac(%s) or type(%s)' % (eth.dst, eth.type))
        try:
            lldp_data = eth.lldp
        except:
            LOG.debug('Invalid LLDP message')
            raise LLDPPacket.LLDPUnknownFormat(msg='Invalid LLDP message')

        chassis_id = lldp_data.tlvs[0]
        if chassis_id.subtype != ChassisID.SUB_LOCALLY_ASSIGNED:
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown chassis id subtype %d' % chassis_id.subtype)
        chassis_id = chassis_id.chassis_id
        if not chassis_id.startswith(LLDPPacket.CHASSIS_ID_PREFIX):
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown chassis id format %s' % chassis_id)
        src_dpid = str_to_dpid(chassis_id[LLDPPacket.CHASSIS_ID_PREFIX_LEN:])

        port_id = lldp_data.tlvs[1]
        if port_id.subtype != PortID.SUB_PORT_COMPONENT:
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown port id subtype %d' % port_id.subtype)
        port_id = port_id.port_id
        if len(port_id) != LLDPPacket.PORT_ID_SIZE:
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown port id %d' % port_id)
        (src_port_no, ) = struct.unpack(LLDPPacket.PORT_ID_STR, port_id)

        sys_name_tlv = lldp_data.tlvs[3]
        if sys_name_tlv.system_name.find(LLDPPacket.SYSTEM_NAME_PREFIX) != 0:
            print "WARNING: Received LLDP w/ sys name: %s" % sys_name_tlv.system_name
            packetID = None
            rtt = None
        else:
            name_segments = sys_name_tlv.system_name.split(';')
            packetID = name_segments[1]
            rtt = name_segments[2] # Ctrl <=> switch RTT

        return src_dpid, src_port_no, packetID, rtt


class Discovery(app_manager.RyuApp):
    _CONTEXTS = {'dpset': dpset.DPSet,
                 'link_set': LinkSet,
                 'port_set': PortSet,
                 'ext_ports': dict,
                 'mac2ext_port': mac_to_port.MacToPortTable,
                 'ofsniff': OFSniff.OFSniff,
                 'dpid2endpoint': dict,
                 'ext_switch_ports': dict
                 }

    # TODO:XXX what's appropriate parameter? adaptive?
    # in seconds
    DEFAULT_TTL = 120   # unused. ignored.
    LLDP_SEND_GUARD = 0.2
    LLDP_SEND_PERIOD_PER_PORT = 4.9
    TIMEOUT_CHECK_PERIOD = 5.
    LINK_TIMEOUT = TIMEOUT_CHECK_PERIOD * 2
    LINK_LLDP_DROP = 5

    LLDP_PACKET_LEN = len(LLDPPacket.lldp_packet(0, 0, mac.DONTCARE, 0))

    OF_CONN_PROBE_PERIOD = float(2) # Period to probe for switch <=> ctrl RTTs

    PACKET_ID_EXPIRY_TIME = 60 # Max lifetime of outstanding packet IDs

    def __init__(self, *args, **kwargs):
        super(Discovery, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        self.link_set = kwargs['link_set']
        self.ext_ports = kwargs['ext_ports'] # Ports not within topology
        self.ext_switch_ports = kwargs['ext_switch_ports'] # External ports connected to another switch
        self.mac2ext_port = kwargs['mac2ext_port']
        self.install_flow = kwargs.get('install_flow',
                                       FLAGS.discovery_install_flow)
        self.explicit_drop = kwargs.get('explicit_drop',
                                        FLAGS.discovery_explicit_drop)

        self.port_set = kwargs['port_set']

        self.dp2RTTSamples = {} # DPID to deque containing ctrl <=> switch RTTs (ms)
        self.dp2avgRTT = {} # DPID to avg ctrl <=> switch RTT (ms)

        self.packetIDs = {} # Outstanding packet IDs <=> timestamp of when they were sent

        self.linkDelaySamples = {} # Map (dpid, port) tuples to deque of delays (ms)

        self.lldp_event = gevent.event.Event()
        self.link_event = gevent.event.Event()
        self.is_active = True
        self.threads = []
        self.threads.append(gevent.spawn_later(0, self.lldp_loop))
        self.threads.append(gevent.spawn_later(0, self.link_loop))
        self.threads.append(gevent.spawn_later(0, self.ext_ports_loop))
        self.threads.append(gevent.spawn_later(0, self.lldp_table_lookup_loop))
        self.threads.append(gevent.spawn_later(0, self.pkt_id_cleanup_loop))

        # OFSniff: startSniffLoop() will start a separate thread, not hindered by GIL
        self.ofsniff = kwargs['ofsniff']
        self.dpid2endpoint = kwargs['dpid2endpoint'] # Maps DPID to numerical endpoint (ip/port)
        assert self.ofsniff.startSniffLoop("any", FLAGS.ofp_tcp_listen_port) == True

    # Periodically clean-up the packetIDs structure
    # This prevents the structure from building up and consuming memory due to
    # packets sent out to host ports or ports connected to external networks
    def pkt_id_cleanup_loop(self):
        while self.is_active:
            now = time.time()
            for pktId, timestamp in self.packetIDs.items():
                expiry_time = timestamp + self.PACKET_ID_EXPIRY_TIME
                if expiry_time < now:
                    self.packetIDs.pop(pktId)

            time.sleep(10) # Not time-critical, sleep 10 seconds

    # Periodically send PacketOut w/ OFPP_TABLE to measure table lookup time + OF connection RTT
    def lldp_table_lookup_loop(self):
        time.sleep(0.5) # Stagger from echo req-replies
        while self.is_active:
            dp_list = self.dpset.dps.values() # Datapath objects
            for dp in dp_list:
                actions = [dp.ofproto_parser.OFPActionOutput(dp.ofproto.OFPP_TABLE)]
                lldp_packet = LLDPPacket.lldp_packet(dp.id, dp.ofproto.OFPP_MAX,
                                                     mac.DONTCARE, self.DEFAULT_TTL)
                lldp_packet, pktId = LLDPPacket.update_packet_id(lldp_packet)
                self.packetIDs[pktId] = time.time()
                dp.send_packet_out(actions=actions, data=lldp_packet)
                gevent.sleep(self.OF_CONN_PROBE_PERIOD / len(dp_list))  # don't burst

            if not dp_list:
                gevent.sleep(self.OF_CONN_PROBE_PERIOD) # Monkey-patched by gevent

    # Keeps ext_ports and ext_switch_ports up to date.
    # Do this within loop rather than triggering on OF port status updates
    # as ports may dynamically become/lose their status as external ports
    #
    # External ports are those seen by OpenFlow, but not part of a link
    # within the topology. These may be connected to hosts or networks
    # not controlled by this controller
    def ext_ports_loop(self):
        while self.is_active:
            dp_list = self.dpset.dps.values() # Datapath objects
            for dp in dp_list:
                ext_port_list = []
                port_list = self.port_set.get_dp_port(dp)
                #print "DPID: %s" % dp.id

                for port in port_list:
                    is_ext_port = True if not self.link_set.port_exists(dp.id, port) else False

                    if is_ext_port:
                        ext_port_list.append(port)

                self.ext_ports[dp.id] = ext_port_list

                # Double-check ext_switch_ports. First LLDP received at one end
                # may mistakenly identify it as an external switch port.
                for port in self.ext_switch_ports.get(dp.id, []):
                    if port not in ext_port_list:
                        self.ext_switch_ports[dp.id].remove(port)

            time.sleep(1)

    def close(self):
        self.is_active = False
        self.lldp_event.set()
        self.link_event.set()
        # gevent.killall(self.threads)
        gevent.joinall(self.threads)

    @handler.set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def dp_handler(self, ev):
        LOG.debug('dp_handler %s %s', ev, ev.enter_leave)
        dp = ev.dp
        if ev.enter_leave: # New switch connected
            ip = dp.address[0].split('.')
            ip.reverse() # Turn to network byte-order
            endpoint = 0
            for octet in ip:
                endpoint = (endpoint << 8) | int(octet)

            endpoint = (endpoint << 16) | dp.address[1]
            self.dpid2endpoint[dp.id] = endpoint

            if self.install_flow:
                rule = nx_match.ClsRule()
                rule.set_dl_dst(lldp.LLDP_MAC_NEAREST_BRIDGE)
                rule.set_dl_type(lldp.ETH_TYPE_LLDP)
                ofproto = dp.ofproto
                ofproto_parser = dp.ofproto_parser
                output = ofproto_parser.OFPActionOutput(
                    ofproto.OFPP_CONTROLLER, max_len=self.LLDP_PACKET_LEN)
                actions = [output]
                dp.send_flow_mod(
                    rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
                    idle_timeout=0, hard_timeout=0,
                    priority=(0x10000 - 1), actions=actions)

    def _port_added(self, dp, port):
        port_no = port.port_no
        lldp_data = LLDPPacket.lldp_packet(
            dp.id, port_no, port.hw_addr, self.DEFAULT_TTL)
        is_down = port_is_down(dp, port)
        self.port_set.add_port(dp, port_no, is_down, lldp_data)
        LOG.debug('_port_added %s %s, %s',
                  dpid_to_str(dp.id), port_no, is_down)

    @handler.set_ev_cls(dpset.EventPortAdd, dpset.DPSET_EV_DISPATCHER)
    def port_add_handler(self, ev):
        dp = ev.dp
        port = ev.port
        if dp.is_reserved_port(port.port_no):
            return
        self._port_added(dp, port)
        self.lldp_event.set()

    def _link_down(self, dp, port_no):
        dpid = dp.id
        try:
            dst = self.link_set.port_deleted(dpid, port_no)
        except KeyError:
            return

        dst_dp = self.dpset.get(dpid)
        if dst_dp is not None:
            self.port_set.move_front(dst_dp, dst.port_no)

    @handler.set_ev_cls(dpset.EventPortDelete, dpset.DPSET_EV_DISPATCHER)
    def port_del_handler(self, ev):
        dp = ev.dp
        port_no = ev.port.port_no
        if dp.is_reserved_port(port_no):
            return
        LOG.debug('port_del %s %d', dp, port_no)
        self.port_set.del_port(dp, port_no)
        self._link_down(dp, port_no)
        self.lldp_event.set()

    @handler.set_ev_cls(dpset.EventPortModify, dpset.DPSET_EV_DISPATCHER)
    def port_modify_handler(self, ev):
        dp = ev.dp
        port = ev.port
        port_no = port.port_no
        if dp.is_reserved_port(port_no):
            return
        is_down = port_is_down(dp, port)
        self.port_set.set_down(dp, port_no, is_down)
        if is_down:
            self._link_down(dp, port_no)
        self.lldp_event.set()

    @staticmethod
    def _drop_packet(msg):
        if msg.buffer_id != 0xffffffff:  # TODO:XXX use constant instead of -1
            msg.datapath.send_packet_out(msg.buffer_id, msg.in_port, [])

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        print "\n"
        now = time.time()
        msg = ev.msg
        dp = msg.datapath
        # LOG.debug('packet in ev %s msg %s', ev, ev.msg)
        try:
            src_dpid, src_port_no, packetID, remote_rtt = LLDPPacket.lldp_parse(msg.data)

            # If in_port is OFPP_MAX, then this was sent from this controller
            # for measuring the connection + table lookup RTT
            if (src_port_no == dp.ofproto.OFPP_MAX):
                # OFSniff implementation
                self.packetIDs.pop(packetID)
                self.dp2avgRTT[dp.id] = self.ofsniff.getDp2CtrlRTT(self.dpid2endpoint[dp.id])
                # END OFSniff implementation

                print "echo to dpid %s avg RTT is %lf ms" % (dp.id, self.dp2avgRTT[dp.id])
                self._drop_packet(msg)
                return;
        except dpkt.UnpackError as e:
            LOG.debug('error in unpack packet %s', e)
        except LLDPPacket.NotLLDP as e:
            # This handler can receive all the packtes which can be
            # not-LLDP packet. Ignore it silently

            # But first, record info about the ingress ports of MACs
            if msg.in_port in self.ext_ports.get(dp.id, []):
                dst, src = struct.unpack_from('!6s6s', buffer(msg.data), 0)

                self.mac2ext_port.dpid_add(dp.id)

                # Find if MAC currently exists, if so, delete it
                # This case may exist if hosts migrate
                for dpid in self.mac2ext_port.mac_to_port.keys():
                    port = self.mac2ext_port.port_get(dpid, src)
                    if port:
                        self.mac2ext_port.mac_del(dpid, src)
                        break

                self.mac2ext_port.port_add(dp.id, msg.in_port, src)

            return
        except LLDPPacket.LLDPUnknownFormat as e:
            # There is some error with the LLDP packet's formatting
            # Drop the packet
            self._drop_packet(msg)
            return
        else:
            from_this_ctrl = src_dpid == dp.id and src_port_no == msg.in_port

            if not from_this_ctrl and not self.link_set.update_link(src_dpid, src_port_no,
                                                                     dp.id, msg.in_port):
                # reverse link is not detected yet.
                # So schedule the check early because it's very likely it's up
                try:
                    self.port_set.lldp_received(dp, msg.in_port)
                except KeyError:
                    # There are races between EventOFPPacketIn and
                    # EventDPPortAdd. So packet-in event can happend before
                    # port add event. In that case key error can happend.
                    LOG.debug('KeyError')
                else:
                    # We've received LLDP, and there's no reverse link, thus we
                    # add this to ext_switch_ports. At Ryu start, it may be
                    # mistakenly identified as one even if the switch at the
                    # end is controlled by this controller. This is checked for
                    # and the port is removed in the ext_ports_loop().
                    self.ext_switch_ports.setdefault(dp.id, []).append(msg.in_port)

                    if src_dpid in self.dpset.dps.keys():
                        # move_front() will clear port_data's timestamp, which will
                        # schedule a new LLDP ASAP. Only do this if source DPID
                        # is also controlled by this controller, else it will spam LLDPs.
                        self.port_set.move_front(dp, msg.in_port)
                    self.lldp_event.set()

            if from_this_ctrl and packetID and remote_rtt:
                # This is a bounced reply packet from remote end
                # Check packet ID to see if this controller sent it
                try:
                    sent_time = self.packetIDs.pop(packetID, 0)
                    avgDelay = self.ofsniff.getLinkLatAvg(self.dpid2endpoint[dp.id], src_port_no)
                    print "avg link rtt: %.6lf ms ; one-way delay: %.6lf ms" % (avgDelay, avgDelay / 2)

                except Exception as e:
                    # Only seen if switch changed controllers between time LLDP sent and bounced back
                    print "Not from this controller! Packet ID was: %s" % packetID # Right now shouldn't see this...
                    print "ERROR is.. %s" % e
                else:
                    print "Packet ID verified from this controller! This RTT: %.6lf & Remote RTT: %s" % (self.dp2avgRTT.get(dp.id, 0), remote_rtt)
                    pass

            elif packetID is not None and remote_rtt is not None:
                # Fill packet with this controller's switch RTT and send it back
                actions = [dp.ofproto_parser.OFPActionOutput(msg.in_port)]
                lldp_packet, _ = LLDPPacket.update_rtt(msg.data, self.dp2avgRTT.get(dp.id, 0))
                dp.send_packet_out(actions=actions, data=lldp_packet)

            else:
                # If packetID or remote_rtt are None, may have received LLDP from system
                # that doesn't support our protocol. Ignore silently for now.
                pass

        if self.explicit_drop:
            self._drop_packet(msg)

    def send_lldp_packet(self, dp, port_no):
        try:
            port_data = self.port_set.lldp_sent(dp, port_no)
        except KeyError as e:
            # port_set can be modified during our sleep in self.lldp_loop()
            LOG.debug('port_set %s key error %s', self.port_set, e)
            return
        if port_data.is_down:
            return
        actions = [dp.ofproto_parser.OFPActionOutput(port_no)]
        lldp_packet, pktId = LLDPPacket.update_packet_id(port_data.data)
        self.packetIDs[pktId] = time.time()
        dp.send_packet_out(actions=actions, data=lldp_packet)
        # LOG.debug('lldp sent %s %d', dpid_to_str(dp.id), port_no)

    def lldp_loop(self):
        while self.is_active:
            self.lldp_event.clear()

            now = time.time()
            timeout = None
            ports_now = []
            ports = []
            # LOG.debug('port_set %s', self.port_set)
            for (key, data) in self.port_set.items():
                if data.timestamp is None:
                    ports_now.append(key)
                    continue

                expire = data.timestamp + self.LLDP_SEND_PERIOD_PER_PORT
                if expire <= now:
                    ports.append(key)
                    continue

                timeout = expire - now
                break

            for (dp, port_no) in ports_now:
                self.send_lldp_packet(dp, port_no)
            for (dp, port_no) in ports:
                self.send_lldp_packet(dp, port_no)
                gevent.sleep(self.LLDP_SEND_GUARD)      # don't burst

            if timeout is not None and ports:
                timeout = 0     # We have already slept
            # LOG.debug('lldp sleep %s', timeout)
            self.lldp_event.wait(timeout=timeout)

    def link_loop(self):
        while self.is_active:
            self.link_event.clear()

            now = time.time()
            deleted = []
            for (link, timestamp) in self.link_set.items():
                # TODO:XXX make link_set ordereddict?
                # LOG.debug('link %s timestamp %d', link, timestamp)
                if timestamp + self.LINK_TIMEOUT < now:
                    src = link.src
                    src_dp = self.dpset.get(src.dpid)
                    if src_dp is not None:
                        port_data = self.port_set.get_port(src_dp,
                                                           src.port_no)
                        LOG.debug('port_data %s', port_data)
                        if port_data.lldp_dropped() > self.LINK_LLDP_DROP:
                            deleted.append(link)

            for link in deleted:
                self.link_set.link_down(link)
                LOG.debug('delete link %s', link)

                dst = link.dst
                rev_link = Link(dst, link.src)
                if rev_link not in deleted:
                    # It is very likely that the reverse link is also
                    # disconnected. Check it early.
                    expire = now - self.LINK_TIMEOUT
                    self.link_set.rev_link_set_timestamp(rev_link, expire)
                    dst_dp = self.dpset.get(dst.dpid)
                    if dst_dp is not None:
                        self.port_set.move_front(dst_dp, dst.port_no)
                        self.lldp_event.set()

            self.link_event.wait(timeout=self.TIMEOUT_CHECK_PERIOD)

