include "dnstable.pxi"

RRSET = DNSTABLE_QUERY_TYPE_RRSET
RDATA_IP = DNSTABLE_QUERY_TYPE_RDATA_IP
RDATA_RAW = DNSTABLE_QUERY_TYPE_RDATA_RAW
RDATA_NAME = DNSTABLE_QUERY_TYPE_RDATA_NAME

class DnstableException(Exception):
    pass

cdef fmt_time(t):
    import time
    return time.strftime('%Y-%m-%d %H:%M:%S -0000', time.gmtime(t))

cdef class entry(object):
    cdef dnstable_entry_type etype
    cdef dict d

    def __init__(self):
        pass

    cdef from_c(self, dnstable_entry *ent, iszone=False):
        cdef dnstable_res res
        cdef uint16_t u16
        cdef uint64_t u64
        cdef uint8_t *data
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
            self.d['rrname'] = PyString_FromStringAndSize(<char *> data, len_data)

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
                self.d['rdata'].append(PyString_FromStringAndSize(<char *> data, len_data))

        if self.etype == DNSTABLE_ENTRY_TYPE_RRSET:
            # bailiwick
            res = dnstable_entry_get_bailiwick(ent, &data, &len_data)
            if res == dnstable_res_success:
                self.d['bailiwick'] = PyString_FromStringAndSize(<char *> data, len_data)

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
            d['rrname'] = wdns.domain_to_str(d['rrname'])
        if 'bailiwick' in d:
            d['bailiwick'] = wdns.domain_to_str(d['bailiwick'])
        if 'rrtype' in d:
            d['rrtype'] = wdns.rrtype_to_str(d['rrtype'])
        return d

    def to_text(self):
        import cStringIO
        import wdns

        s = cStringIO.StringIO()

        if self.etype == DNSTABLE_ENTRY_TYPE_RRSET:
            if 'bailiwick' in self.d:
                s.write(';;  bailiwick: %s\n' % wdns.domain_to_str(self.d['bailiwick']))

            if 'count' in self.d:
                s.write(';;      count: %d\n' % self.d['count'])

            if 'zone_time_first' in self.d:
                s.write(';; first seen in zone file: %s\n' % fmt_time(self.d['zone_time_first']))

            if 'zone_time_last' in self.d:
                s.write(';;  last seen in zone file: %s\n' % fmt_time(self.d['zone_time_last']))

            if 'time_first' in self.d:
                s.write(';; first seen: %s\n' % fmt_time(self.d['time_first']))

            if 'time_last' in self.d:
                s.write(';;  last seen: %s\n' % fmt_time(self.d['time_last']))

        if 'rdata' in self.d:
            for rdata in self.d['rdata']:
                s.write(wdns.domain_to_str(self.d['rrname']))
                s.write(' IN ')
                s.write(wdns.rrtype_to_str(self.d['rrtype']))
                s.write(' ')
                s.write(repr(wdns.rdata(rdata, wdns.CLASS_IN, self.d['rrtype'])))
                s.write('\n')

        s.seek(0)
        return s.read()

    def to_json(self):
        import json
        return json.dumps(self.to_fmt_dict())

@cython.internal
cdef class iteritems(object):
    cdef dnstable_iter *_instance
    cdef object iszone
    cdef object q

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
        d = entry()
        d.from_c(ent, self.iszone)
        dnstable_entry_destroy(&ent)
        return d

cdef class query(object):
    cdef dnstable_query *_instance
    cdef readonly str rrtype
    cdef readonly str bailiwick

    def __cinit__(self):
        self._instance = NULL

    def __init__(self, qtype, str data, str rrtype=None, str bailiwick=None):
        cdef dnstable_res
        self.rrtype = rrtype
        self.bailiwick = bailiwick

        if not qtype in (RRSET, RDATA_IP, RDATA_RAW, RDATA_NAME):
            raise DnstableException, 'invalid qtype'
        self._instance = dnstable_query_init(qtype)

        res = dnstable_query_set_data(self._instance, PyString_AsString(data))
        if res != dnstable_res_success:
            raise DnstableException, 'dnstable_query_set_data() failed: %s' % dnstable_query_get_error(self._instance)

        if rrtype:
            res = dnstable_query_set_rrtype(self._instance, PyString_AsString(rrtype))
            if res != dnstable_res_success:
                raise DnstableException, 'dnstable_query_set_rrtype() failed: %s' % dnstable_query_get_error(self._instance)

        if qtype == RRSET and bailiwick:
            res = dnstable_query_set_bailiwick(self._instance, PyString_AsString(bailiwick))
            if res != dnstable_res_success:
                raise DnstableException, 'dnstable_query_set_bailiwick() failed: %s' % dnstable_query_get_error(self._instance)

    def __dealloc__(self):
        dnstable_query_destroy(&self._instance)

cdef class reader(object):
    cdef dnstable_reader *_instance
    cdef object iszone

    def __cinit__(self):
        self._instance = NULL

    def __dealloc__(self):
        dnstable_reader_destroy(&self._instance)

    def __init__(self, bytes fname, iszone=False):
        import os
        if not os.path.isfile(fname):
            raise DnstableException, 'cannot open file %s' % fname
        self._instance = dnstable_reader_init_fname(PyString_AsString(fname))
        self.iszone = iszone

    def query(self, query q):
        it = iteritems(self.iszone)
        it._instance = dnstable_reader_query(self._instance, q._instance)
        it.q = q
        return it
