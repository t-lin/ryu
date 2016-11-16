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

import logging
import time

from ryu.controller import dispatcher
from ryu.controller import event
from ryu.lib import dpid as lib_dpid


LOG = logging.getLogger(__name__)


QUEUE_NAME_LINK_SET = 'link_set'
DISPATCHER_NAME_LINK_SET = 'link_set'
LINK_SET_EV_DISPATCHER = dispatcher.EventDispatcher(DISPATCHER_NAME_LINK_SET)


class DPPort(object):
    def __init__(self, dpid, port_no):
        super(DPPort, self).__init__()
        self.dpid = dpid
        self.port_no = port_no

    # this type is used for key value of LinkSet
    def __eq__(self, other):
        return self.dpid == other.dpid and self.port_no == other.port_no

    def __hash__(self):
        return hash((self.dpid, self.port_no))

    def __str__(self):
        return 'DPPort<%s, %d>' % (lib_dpid.dpid_to_str(self.dpid),
                                   self.port_no)


class Link(object):
    def __init__(self, src, dst):
        super(Link, self).__init__()
        self.src = src
        self.dst = dst

    # this type is used for key value of LinkSet
    def __eq__(self, other):
        return self.src == other.src and self.dst == other.dst

    def __hash__(self):
        return hash((self.src, self.dst))

    def __str__(self):
        return 'LINK<%s, %s>' % (self.src, self.dst)


class LinkEvent(event.EventBase):
    def __init__(self, link, add_del):
        # add_del
        # True: link is added
        # False: link is removed
        super(LinkEvent, self).__init__()
        self.link = link
        self.add_del = add_del

    def __str__(self):
        return 'LinkEvent<%s, %s>' % (self.link, self.add_del)


class LinkSet(dict):
    """
    dict: Link -> timestamp
    """
    def __init__(self):
        super(LinkSet, self).__init__()
        self._map = {}
        self.ev_q = dispatcher.EventQueue(QUEUE_NAME_LINK_SET,
                                          LINK_SET_EV_DISPATCHER)

    def update_link(self, src_dpid, src_port_no, dst_dpid, dst_port_no):
        src = DPPort(src_dpid, src_port_no)
        dst = DPPort(dst_dpid, dst_port_no)
        link = Link(src, dst)

        if link not in self:
            self.ev_q.queue(LinkEvent(link, True))
        self[link] = time.time()
        self._map[src] = dst

        # return if the reverse link is also up or not
        rev_link = Link(dst, src)
        return rev_link in self

    def link_down(self, link):
        del self[link]
        del self._map[link.src]
        self.ev_q.queue(LinkEvent(link, False))

    def rev_link_set_timestamp(self, rev_link, timestamp):
        # rev_link may or may not in LinkSet
        if rev_link in self:
            self[rev_link] = timestamp

    def port_deleted(self, dpid, port_no):
        src = DPPort(dpid, port_no)
        dst = self._map.get(src, None)
        if dst is None:
            raise KeyError()

        link = Link(src, dst)
        rev_link = Link(dst, src)

        del self[link]
        del self._map[src]
        # reverse link might not exist
        self.pop(rev_link, None)
        rev_link_dst = self._map.pop(dst, None)

        self.ev_q.queue(LinkEvent(link, False))
        if rev_link_dst is not None:
            self.ev_q.queue(LinkEvent(rev_link, False))

        return dst

    # for discovery REST API
    def get_items(self, dpid=None):
        if dpid is None:
            return self.items()

        return ((link, ts) for (link, ts) in self.items()
                if (link.src.dpid == dpid or link.dst.dpid == dpid))
