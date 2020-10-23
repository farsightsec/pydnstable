#cython: embedsignature=True
#cython: language_level=2
# Copyright (c) 2015-2019 by Farsight Security, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

include "dnstable.pxi"

import math

RRSET = DNSTABLE_QUERY_TYPE_RRSET
RDATA_IP = DNSTABLE_QUERY_TYPE_RDATA_IP
RDATA_RAW = DNSTABLE_QUERY_TYPE_RDATA_RAW
RDATA_NAME = DNSTABLE_QUERY_TYPE_RDATA_NAME

class DnstableException(Exception):
    pass

class Timeout(DnstableException):
    pass

cdef class entry(object):
    cdef dnstable_entry *_instance
    cdef dnstable_entry_type etype
    cdef dict d

    def __cinit__(self):
        self._instance = NULL

    def __dealloc__(self):
        dnstable_entry_destroy(&self._instance)

    def __init__(self):
        pass

    cdef from_c(self, dnstable_entry *ent, iszone=False):
        cdef dnstable_res res
        cdef uint16_t u16
        cdef uint64_t u64
        cdef const uint8_t *data
        cdef size_t len_data
        cdef size_t sz
        cdef size_t i

        self.d = {}
        self.etype = dnstable_entry_get_type(ent)

        if not self.etype in (DNSTABLE_ENTRY_TYPE_RRSET, DNSTABLE_ENTRY_TYPE_RDATA):
            raise DnstableException, 'unhandled entry type'

        # rrname
        res = dnstable_entry_get_rrname(ent, &data, &len_data)
        if res == dnstable_res_success:
            self.d['rrname'] = data[:len_data]

        # rrtype
        res = dnstable_entry_get_rrtype(ent, &u16)
        if res == dnstable_res_success:
            self.d['rrtype'] = u16

        # count
        res = dnstable_entry_get_count(ent, &u64)
        if res == dnstable_res_success:
            self.d['count'] = u64

        # time_first
        res = dnstable_entry_get_time_first(ent, &u64)
        if res == dnstable_res_success:
            if iszone:
                self.d['zone_time_first'] = u64
            else:
                self.d['time_first'] = u64

        # time_last
        res = dnstable_entry_get_time_last(ent, &u64)
        if res == dnstable_res_success:
            if iszone:
                self.d['zone_time_last'] = u64
            else:
                self.d['time_last'] = u64

        # rdata
        res = dnstable_entry_get_num_rdata(ent, &sz)
        if res == dnstable_res_success:
            self.d['rdata'] = []
            for i from 0 <= i < sz:
                res = dnstable_entry_get_rdata(ent, i, &data, &len_data)
                if res != dnstable_res_success:
                    raise DnstableException, 'dnstable_entry_get_rdata() failed'
                self.d['rdata'].append(data[:len_data])

        if self.etype == DNSTABLE_ENTRY_TYPE_RRSET:
            # bailiwick
            res = dnstable_entry_get_bailiwick(ent, &data, &len_data)
            if res == dnstable_res_success:
                self.d['bailiwick'] = data[:len_data].decode('utf-8')

        if iszone:
            dnstable_entry_set_iszone(ent, iszone)

        self._instance = ent

    def __repr__(self):
        return self.to_text()

    def to_dict(self):
        return self.d

    def to_fmt_dict(self):
        import copy
        import wdns
        d = copy.deepcopy(self.d)
        if 'rdata' in d:
            new_rdata_list = []
            for rdata in d['rdata']:
                new_rdata_list.append(repr(wdns.rdata(rdata, wdns.CLASS_IN, self.d['rrtype'])))
            d['rdata'] = new_rdata_list
        if 'rrname' in d:
            d['rrname'] = wdns.domain_to_str(d['rrname'].encode('utf-8'))
        if 'bailiwick' in d:
            d['bailiwick'] = wdns.domain_to_str(d['bailiwick'].encode('utf-8'))
        if 'rrtype' in d:
            d['rrtype'] = wdns.rrtype_to_str(d['rrtype'])
        return d

    def to_text(self):
        cdef char *res
        res = dnstable_entry_to_text(self._instance)
        s = res.decode('utf-8')
        free(res)
        return s

    def to_json(self, rfc3339_time = False, rdata_always_array = False):
        cdef char *res
        cdef dnstable_formatter *f

        if not rfc3339_time and not rdata_always_array:
            # for typical case, use simply C function
            res = dnstable_entry_to_json(self._instance)
            s = res.decode('utf-8')
            free(res)
            return s
        else:
            # create and destroy the formatter each time
            f = dnstable_formatter_init()
            dnstable_formatter_set_output_format(f, dnstable_output_format_json)
            if rfc3339_time:
                dnstable_formatter_set_date_format(f, dnstable_date_format_rfc3339)
            else:
                dnstable_formatter_set_date_format(f, dnstable_date_format_unix)
            dnstable_formatter_set_rdata_array(f, rdata_always_array)

            res = dnstable_entry_format(f, self._instance)
            s = res.decode('utf-8')
            free(res)
            dnstable_formatter_destroy(&f)
            return s

@cython.internal
cdef class iteritems(object):
    cdef dnstable_iter *_instance
    cdef object iszone

    def __cinit__(self):
        self._instance = NULL

    def __init__(self, iszone=False):
        self.iszone = iszone

    def __dealloc__(self):
        dnstable_iter_destroy(&self._instance)

    def __iter__(self):
        return self

    def __next__(self):
        cdef dnstable_res res
        cdef dnstable_entry *ent

        if self._instance == NULL:
            raise StopIteration

        res = dnstable_iter_next(self._instance, &ent)

        if res == dnstable_res_failure:
            raise StopIteration
        elif res == dnstable_res_timeout:
            raise Timeout

        d = entry()
        d.from_c(ent, self.iszone)
        return d

cdef class query(object):
    cdef dnstable_query *_instance
    cdef readonly int qtype
    cdef readonly str data
    cdef readonly str rrtype
    cdef readonly str bailiwick

    def __cinit__(self):
        self._instance = NULL

    def __init__(self, qtype, str data, str rrtype=None, str bailiwick=None, time_first_before=None, time_first_after=None, time_last_before=None, time_last_after=None, timeout=None, aggregate=True, uint64_t offset=0):
        cdef dnstable_res
        cdef timespec ts
        cdef uint64_t tm

        self.data = data
        self.rrtype = rrtype
        self.bailiwick = bailiwick

        if not qtype in (RRSET, RDATA_IP, RDATA_RAW, RDATA_NAME):
            raise DnstableException, 'invalid qtype'
        self._instance = dnstable_query_init(qtype)
        self.qtype = qtype

        res = dnstable_query_set_data(self._instance, data.encode('UTF-8'))
        if res != dnstable_res_success:
            raise DnstableException, 'dnstable_query_set_data() failed: %s' % dnstable_query_get_error(self._instance)

        if rrtype:
            res = dnstable_query_set_rrtype(self._instance, rrtype.encode('UTF-8'))
            if res != dnstable_res_success:
                raise DnstableException, 'dnstable_query_set_rrtype() failed: %s' % dnstable_query_get_error(self._instance)

        if offset != 0:
            res = dnstable_query_set_offset(self._instance, offset)
            if res != dnstable_res_success:
                raise DnstableException, 'dnstable_query_set_offset() failed: %s' % dnstable_query_get_error(self._instance)

        res = dnstable_query_set_aggregated(self._instance, aggregate)
        if res != dnstable_res_success:
            raise DnstableException, 'dnstable_query_set_aggregated() failed: %s' % dnstable_query_get_error(self._instance)

        if qtype == RRSET and bailiwick:
            res = dnstable_query_set_bailiwick(self._instance, bailiwick.encode('UTF-8'))
            if res != dnstable_res_success:
                raise DnstableException, 'dnstable_query_set_bailiwick() failed: %s' % dnstable_query_get_error(self._instance)

        if timeout:
            timeout = float(timeout)
            if timeout < 0:
                raise ValueError('timeout ({}) is not a positive number'.format(timeout))
            ts.tv_sec = math.trunc(timeout)
            ts.tv_nsec = math.modf(timeout)[0] * 1e9
            res = dnstable_query_set_timeout(self._instance, &ts)
            if res != dnstable_res_success:
                raise DnstableException, 'dnstable_query_set_timeout() failed: %s' % dnstable_query_get_error(self._instance)

        if time_first_before is not None:
            try:
                tm = time_first_before
            except OverflowError:
                raise DnstableException, 'overflow error converting time_first_before %s' % (time_first_before)
            res = dnstable_query_set_filter_parameter(self._instance,
                    DNSTABLE_FILTER_PARAMETER_TIME_FIRST_BEFORE, &tm, 8)
            if res != dnstable_res_success:
                raise DnstableException, 'dnstable_query_set_filter_parameter(time_first_before) failed'

        if time_first_after is not None:
            try:
                tm = time_first_after
            except OverflowError:
                raise DnstableException, 'overflow error converting time_first_after %s' % (time_first_after)
            res = dnstable_query_set_filter_parameter(self._instance,
                    DNSTABLE_FILTER_PARAMETER_TIME_FIRST_AFTER, &tm, 8)
            if res != dnstable_res_success:
                raise DnstableException, 'dnstable_query_set_filter_parameter(time_first_after) failed'

        if time_last_before is not None:
            try:
                tm = time_last_before
            except OverflowError:
                raise DnstableException, 'overflow error converting time_last_before %s' % (time_last_before)
            res = dnstable_query_set_filter_parameter(self._instance,
                    DNSTABLE_FILTER_PARAMETER_TIME_LAST_BEFORE, &tm, 8)
            if res != dnstable_res_success:
                raise DnstableException, 'dnstable_query_set_filter_parameter(time_last_before) failed'

        if time_last_after is not None:
            try:
                tm = time_last_after
            except OverflowError:
                raise DnstableException, 'overflow error converting time_last_after %s' % (time_last_after)
            res = dnstable_query_set_filter_parameter(self._instance,
                    DNSTABLE_FILTER_PARAMETER_TIME_LAST_AFTER, &tm, 8)
            if res != dnstable_res_success:
                raise DnstableException, 'dnstable_query_set_filter_parameter(time_last_after) failed'

    def __dealloc__(self):
        dnstable_query_destroy(&self._instance)

    def __repr__(self):
        if self.qtype == RDATA_IP:
            s = 'ip '
        elif self.qtype == RDATA_NAME:
            s = 'name '
        elif self.qtype == RDATA_RAW:
            s = 'raw '
        else:
            s = ''

        s += self.data
        if self.rrtype and self.rrtype.lower() != 'any':
            s += '/' + self.rrtype.upper()
        if self.bailiwick:
            if (not self.rrtype) or (self.rrtype and self.rrtype.lower() == 'any'):
                s += '/ANY'
            s += '/' + self.bailiwick
        return s

cdef class reader(object):
    cdef dnstable_reader *_instance
    cdef object iszone

    def __cinit__(self):
        self._instance = NULL

    def __dealloc__(self):
        dnstable_reader_destroy(&self._instance)

    def __init__(self, str fname, iszone=False):
        import os
        if not os.path.isfile(fname.encode('UTF-8')):
            raise DnstableException, 'cannot open file %s' % fname
        self._instance = dnstable_reader_init_setfile(fname.encode('UTF-8'))
        self.iszone = iszone

    def reload(self):
        dnstable_reader_reload_setfile(self._instance)

    def query(self, query q):
        it = iteritems(self.iszone)

        it._instance = dnstable_reader_query(self._instance, q._instance)
        return it
