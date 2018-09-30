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
                          TTL)
from ryu.ofproto import nx_match


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
        self.data = data
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

    @staticmethod
    def lldp_packet(dpid, port_no, dl_addr, ttl):
        tlv_chassis_id = ChassisID(subtype=ChassisID.SUB_LOCALLY_ASSIGNED,
                                   chassis_id=LLDPPacket.CHASSIS_ID_FMT %
                                   dpid_to_str(dpid))

        tlv_port_id = PortID(subtype=PortID.SUB_PORT_COMPONENT,
                             port_id=struct.pack(LLDPPacket.PORT_ID_STR,
                                                 port_no))

        tlv_ttl = TTL(ttl=ttl)
        tlv_end = End()

        tlvs = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_end)
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

        return src_dpid, src_port_no


class Discovery(app_manager.RyuApp):
    _CONTEXTS = {'dpset': dpset.DPSet,
                 'link_set': LinkSet,
                 'ext_ports': dict,
                 'mac2ext_port': mac_to_port.MacToPortTable,
                 }

    # TODO:XXX what's appropriate parameter? adaptive?
    # in seconds
    DEFAULT_TTL = 120   # unused. ignored.
    LLDP_SEND_GUARD = .05
    LLDP_SEND_PERIOD_PER_PORT = .9
    TIMEOUT_CHECK_PERIOD = 5.
    LINK_TIMEOUT = TIMEOUT_CHECK_PERIOD * 2
    LINK_LLDP_DROP = 5

    LLDP_PACKET_LEN = len(LLDPPacket.lldp_packet(0, 0, mac.DONTCARE, 0))

    RTT_SAMPLE_WINDOW = 60

    def __init__(self, *args, **kwargs):
        super(Discovery, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        self.link_set = kwargs['link_set']
        self.ext_ports = kwargs['ext_ports'] # Ports not within topology
        self.mac2ext_port = kwargs['mac2ext_port']
        self.install_flow = kwargs.get('install_flow',
                                       FLAGS.discovery_install_flow)
        self.explicit_drop = kwargs.get('explicit_drop',
                                        FLAGS.discovery_explicit_drop)

        self.port_set = PortSet()

        self.dp2rttSamples = {} # DPID to deque containing ctrl <=> switch RTTs
        self.dp2avgRTT = {} # DPID to avg ctrl <=> switch RTT

        self.lldp_event = gevent.event.Event()
        self.link_event = gevent.event.Event()
        self.is_active = True
        self.threads = []
        self.threads.append(gevent.spawn_later(0, self.lldp_loop))
        self.threads.append(gevent.spawn_later(0, self.link_loop))
        self.threads.append(gevent.spawn_later(0, self.ext_ports_loop))
        self.threads.append(gevent.spawn_later(0, self.of_conn_rtt_loop))

    # Periodically send OFP Echo Requests to the switches
    def of_conn_rtt_loop(self):
        while True:
            dp_list = self.dpset.dps.values() # Datapath objects
            for dp in dp_list:
                echo_req = dp.ofproto_parser.OFPEchoRequest(dp)
                echo_req.data = "%lf" % time.time() # Regular str() function rounds
                dp.send_msg(echo_req)
                gevent.sleep(self.LLDP_SEND_GUARD)  # don't burst

            time.sleep(1)

    @handler.set_ev_cls(ofp_event.EventOFPEchoReply,
        [handler.HANDSHAKE_DISPATCHER, handler.CONFIG_DISPATCHER, handler.MAIN_DISPATCHER])
    def echo_reply_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        rtt = (time.time() - float(msg.data)) * 1000 # RTT in ms
        rtt_samples = self.dp2rttSamples.setdefault(datapath.id, deque())
        avg_rtt = self.dp2avgRTT.get(datapath.id, 0)

        rtt_samples.append(rtt)
        if len(rtt_samples) >= self.RTT_SAMPLE_WINDOW:
            # Simple moving avg
            self.dp2avgRTT[datapath.id] = avg_rtt + \
                ((rtt - rtt_samples.popleft()) / self.RTT_SAMPLE_WINDOW)
        else:
            self.dp2avgRTT[datapath.id] = sum(rtt_samples) / len(rtt_samples)

        #LOG.debug("echo to dpid %s avg RTT is %lf ms" % (datapath.id, self.dp2avgRTT[datapath.id]))


    # Keeps data structure of external ports up to date
    # Do this within loop rather than triggering on OF port status updates
    # as ports may dynamically become/lose their status as external ports
    #
    # External ports are those seen by OpenFlow, but not part of a link
    # within the topology. These may be connected to hosts or networks
    # not controlled by this controller
    def ext_ports_loop(self):
        while True:
            dp_list = self.dpset.dps.values() # Datapath objects
            for dp in dp_list:
                ext_port_list = []
                port_list = self.port_set.get_dp_port(dp)
                #print "DPID: %s" % dp.id

                for port in port_list:
                    #status = "Down" if self.port_set.get_port(dp, port).is_down else "Up"
                    #print "\tPort %s, status = %s, connected to host %s" % (port, status, host_port)
                    host_port = True if not self.link_set.port_exists(dp.id, port) else False

                    if host_port:
                        ext_port_list.append(port)

                self.ext_ports[dp.id] = ext_port_list

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
        if ev.enter_leave:
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
        msg = ev.msg
        # LOG.debug('packet in ev %s msg %s', ev, ev.msg)
        try:
            src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
        except dpkt.UnpackError as e:
            LOG.debug('error in unpack packet %s', e)
        except LLDPPacket.NotLLDP as e:
            # This handler can receive all the packtes which can be
            # not-LLDP packet. Ignore it silently

            # But first, record info about the ingress ports of MACs
            if msg.in_port in self.ext_ports.get(msg.datapath.id, []):
                dst, src = struct.unpack_from('!6s6s', buffer(msg.data), 0)

                self.mac2ext_port.dpid_add(msg.datapath.id)

                # Find if MAC currently exists, if so, delete it
                # This case may exist if hosts migrate
                for dpid in self.mac2ext_port.mac_to_port.keys():
                    port = self.mac2ext_port.port_get(dpid, src)
                    if port:
                        self.mac2ext_port.mac_del(dpid, src)
                        break

                self.mac2ext_port.port_add(msg.datapath.id, msg.in_port, src)

            return
        except LLDPPacket.LLDPUnknownFormat as e:
            # There is some error with the LLDP packet's formatting
            # Drop the packet
            self._drop_packet(msg)
            return
        else:
            if not self.link_set.update_link(src_dpid, src_port_no,
                                             msg.datapath.id, msg.in_port):
                # reverse link is not detected yet.
                # So schedule the check early because it's very likely it's up
                try:
                    self.port_set.lldp_received(msg.datapath, msg.in_port)
                except KeyError:
                    # There are races between EventOFPPacketIn and
                    # EventDPPortAdd. So packet-in event can happend before
                    # port add event. In that case key error can happend.
                    LOG.debug('KeyError')
                else:
                    self.port_set.move_front(msg.datapath, msg.in_port)
                    self.lldp_event.set()
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
        dp.send_packet_out(actions=actions, data=port_data.data)
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

