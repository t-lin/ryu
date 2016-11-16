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


class LinkedDict(dict):
    """
    Doubly Linked List + (subset of) OrderedDict. Inspired from OrderedDict.
    OrderedDict doesn't provide list manipulation.
    """
    _PREV = 0
    _NEXT = 1
    _KEY = 2

    def __init__(self):
        super(LinkedDict, self).__init__()
        self.__root = root = []         # sentinel node
        root[:] = [root, root, None]    # [_PREV, _NEXT, _KEY]
                                        # doubly linked list
        self.__map = {}

    def _remove_key(self, key):
        link_prev, link_next, key = self.__map.pop(key)
        link_prev[self._NEXT] = link_next
        link_next[self._PREV] = link_prev

    def _append_key(self, key):
        root = self.__root
        last = root[self._PREV]
        last[self._NEXT] = root[self._PREV] = self.__map[key] = [last, root,
                                                                 key]

    def _prepend_key(self, key):
        root = self.__root
        first = root[self._NEXT]
        first[self._PREV] = root[self._NEXT] = self.__map[key] = [root, first,
                                                                  key]

    def __setitem__(self, key, value):
        self._append_key(key)
        super(LinkedDict,self).__setitem__(key, value)

    def __delitem__(self, key):
        super(LinkedDict,self).__delitem__(key)
        self._remove_key(key)

    def prepend(self, key, value):
        self._prepend_key(key)
        super(LinkedDict,self).__setitem__(key, value)

    def move_key_last(self, key):
        self._remove_key(key)
        self._append_key(key)

    def move_key_front(self, key):
        self._remove_key(key)
        self._prepend_key(key)

    def clear(self):
        for node in self.__map.itervalues():
            del node[:]
        root = self.__root
        root[:] = [root, root, None]
        self.__map.clear()
        super(LinkedDict,self).clear(self)

    def __iter__(self):
        root = self.__root
        curr = root[self._NEXT]
        while curr is not root:
            yield curr[self._KEY]
            curr = curr[self._NEXT]

    def items(self):
        'ld.items() -> list of (key, value) pairs in ld'
        return [(key, self[key]) for key in self]
