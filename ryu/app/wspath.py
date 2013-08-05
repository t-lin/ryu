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

from ryu.app.wsapi import WSPathComponent
from ryu.app.wsapi import WSPathExtractResult


def extract_string(pc):
    if pc == None:
        return WSPathExtractResult(error="End of requested URI")

    return WSPathExtractResult(value=pc)


def extract_int(pc, base=10, max_value=None):
    if pc == None:
        return WSPathExtractResult(error='End of requested URI')

    try:
        intval = int(pc, base)
    except ValueError:
        return WSPathExtractResult(error='Invalid format: %s' % pc)

    if max_value is not None and intval > max_value:
        return WSPathExtractResult(
            error='value is too big: 0x%x > 0x%x' % (intval, max_value))

    if intval < 0:
        return WSPathExtractResult(error='value must be non-negative: %s' % pc)

    return WSPathExtractResult(value=intval)


class WSPathInt(WSPathComponent):
    _name = None  # must be set by sub class
    _base = 10
    _max_value = None

    def __str__(self):
        assert self._name is not None
        return self._name

    def extract(self, pc, _data):
        return extract_int(pc, self._base, self._max_value)


NETWORK_ID = '{network-id}'


class WSPathNetwork(WSPathComponent):
    """ Match a network id string """
    def __str__(self):
        return NETWORK_ID

    def extract(self, pc, _data):
        return extract_string(pc)


_DPID_LEN = 16
DPID_FMT = '%0' + str(_DPID_LEN) + 'x'
DPID = '{dpid}'


class WSPathSwitch(WSPathInt):
    """ match a switch id string """
    _base = 16

    def __init__(self, name):
        super(WSPathSwitch, self).__init__()
        self._name = name

    def extract(self, pc, data):
        if pc is not None and len(pc) != _DPID_LEN:
            return WSPathExtractResult(error='Invalid format: %s' % pc)
        return super(WSPathSwitch, self).extract(pc, data)


PORT_NO = '{port-no}'


class WSPathPort(WSPathInt):
    """ Match a {port-no} number """
    _name = PORT_NO
