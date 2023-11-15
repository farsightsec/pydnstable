#!/usr/bin/env python

# Copyright (c) 2009-2019 by Farsight Security, Inc.
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

from __future__ import print_function
import unittest
from dnstable import *
import json


class TestDNStable(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = reader("tests/test-dns.fileset")
        assert cls.r is not None

    @classmethod
    def cmp(cls, expectlist, gotlist):
        '''Compare lists of dictionaries, insensitive to the order of the
        lists.  All elements in expectlist must be identical to
        gotlist.
        '''
        for x in expectlist:
            if not [k for k in x if x[k] != gotlist[k]]:
                return True
        return False

    def run_query_rdata_can_be_string(self, q, expect):
        gotsomething = False
        for i in self.r.query(q):
            gotsomething = True
            assert TestDNStable.cmp(expect, json.loads(i.to_json())), \
                "expect-one-of:\n    {}\ngot: {}".format(expect, i.to_json())
        assert gotsomething, "Query returned no results"

    def run_query_rdata_always_array(self, q, expect):
        gotsomething = False
        for i in self.r.query(q):
            gotsomething = True
            assert TestDNStable.cmp(expect, json.loads(i.to_json(rdata_always_array = True))), \
                "expect-one-of:\n    {}\ngot: {}".format(expect, i.to_json(rdata_always_array = True))
        assert gotsomething, "Query returned no results"

    def run_query_rfc3339_time(self, q, expect):
        gotsomething = False
        for i in self.r.query(q):
            gotsomething = True
            assert TestDNStable.cmp(expect, json.loads(i.to_json(rfc3339_time = True))), \
                "expect-one-of:\n    {}\ngot: {}".format(expect, i.to_json(rfc3339_time = True))
        assert gotsomething, "Query returned no results"

    def test_query_rrset_fqdn(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"www.example.com.","rrtype":"A","bailiwick":"example.com.","rdata":["198.51.100.3","198.51.100.4"]},
                  {"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"www.example.com.","rrtype":"AAAA","bailiwick":"example.com.","rdata":["2001:db8::1","2001:db8::2"]}]
        q = query(RRSET, 'www.example.com')
        self.run_query_rdata_can_be_string(q, expect)

    def test_query_rrset_domain(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"NS","bailiwick":"example.com.","rdata":["ns1.example.com.","ns2.example.com."]},
                  {"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"SOA","bailiwick":"example.com.","rdata":["hidden-master.example.com. hostmaster.example.com. 2018032701 30 30 86400 300"]},
                  {"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"MX","bailiwick":"example.com.","rdata":["10 mail.example.com.","20 mail2.example.com."]}]
        q = query(RRSET, 'example.com')
        self.run_query_rdata_can_be_string(q, expect)

    def test_query_rrset_a(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"www.example.com.","rrtype":"A","bailiwick":"example.com.","rdata":["198.51.100.3","198.51.100.4"]}]
        q = query(RRSET, 'www.example.com', rrtype='A')
        self.run_query_rdata_can_be_string(q, expect)

    def test_query_rrset_aaaa(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"www.example.com.","rrtype":"AAAA","bailiwick":"example.com.","rdata":["2001:db8::1","2001:db8::2"]}]
        q = query(RRSET, 'www.example.com', rrtype='AAAA')
        self.run_query_rdata_can_be_string(q, expect)

    def test_query_rrset_ns(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"NS","bailiwick":"example.com.","rdata":["ns1.example.com.","ns2.example.com."]}]
        q = query(RRSET, 'example.com', rrtype='NS')
        self.run_query_rdata_can_be_string(q, expect)

    def test_query_rrset_soa(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"SOA","bailiwick":"example.com.","rdata":["hidden-master.example.com. hostmaster.example.com. 2018032701 30 30 86400 300"]}]
        q = query(RRSET, 'example.com', rrtype='SOA')
        self.run_query_rdata_can_be_string(q, expect)

    def test_query_rrset_mx(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"MX","bailiwick":"example.com.","rdata":["10 mail.example.com.","20 mail2.example.com."]}]
        q = query(RRSET, 'example.com', rrtype='MX')
        self.run_query_rdata_can_be_string(q, expect)

    def test_query_rrset_srv(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"_ldap._tcp.example.com.","rrtype":"SRV","bailiwick":"example.com.","rdata":["10 1 389 ldap.example.com."]}]
        q = query(RRSET, '_ldap._tcp.example.com', rrtype='SRV')
        self.run_query_rdata_can_be_string(q, expect)

    def test_query_rrdata_ipv4(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"www.example.com.","rrtype":"A","rdata":"198.51.100.3"}]
        q = query(RDATA_IP, '198.51.100.3')
        self.run_query_rdata_can_be_string(q, expect)

    def test_query_rrdata_ipv6(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"www.example.com.","rrtype":"AAAA","rdata":"2001:db8::1"}]
        q = query(RDATA_IP, '2001:db8::1')
        self.run_query_rdata_can_be_string(q, expect)

    def test_query_rrdata_name_mx(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"MX","rdata":"10 mail.example.com."}]
        q = query(RDATA_NAME, 'mail.example.com')
        self.run_query_rdata_can_be_string(q, expect)

    def test_query_rrdata_name_ns(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"NS","rdata":"ns1.example.com."}]
        q = query(RDATA_NAME, 'ns1.example.com')
        self.run_query_rdata_can_be_string(q, expect)

    def test_query_rrdata_name_wc(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"NS","rdata":"ns1.example.com."},
                  {"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"NS","rdata":"ns2.example.com."},
                  {"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"_ldap._tcp.example.com.","rrtype":"SRV","rdata":"10 1 389 ldap.example.com."},
                  {"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"MX","rdata":"10 mail.example.com."},
                  {"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"MX","rdata":"20 mail2.example.com."},
                  {"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"SOA","rdata":"hidden-master.example.com. hostmaster.example.com. 2018032701 30 30 86400 300"},
                  {"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"_wildcard_.example.com.","rrtype":"NS","rdata":"foo1.example.com."},
                  {"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"_WILDCARD_.example.com.","rrtype":"NS","rdata":"foo2.example.com."}]
        q = query(RDATA_NAME, '*.example.com')
        self.run_query_rdata_can_be_string(q, expect)

    def test_query_rrdata_name_soa(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"SOA","rdata":"hidden-master.example.com. hostmaster.example.com. 2018032701 30 30 86400 300"}]
        q = query(RDATA_NAME, 'hidden-master.example.com', rrtype='SOA')
        self.run_query_rdata_can_be_string(q, expect)

    def test_query_rrdata_name_soa_wc(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"SOA","rdata":"hidden-master.example.com. hostmaster.example.com. 2018032701 30 30 86400 300"}]
        q = query(RDATA_NAME, '*.example.com', rrtype='SOA')
        self.run_query_rdata_can_be_string(q, expect)

    def test_query_rrdata_name_ldap(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"_ldap._tcp.example.com.","rrtype":"SRV","rdata":"10 1 389 ldap.example.com."}]
        q = query(RDATA_NAME, 'ldap.example.com')
        self.run_query_rdata_can_be_string(q, expect)

    def test_rdata_always_array_query_rrdata_ipv4(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"www.example.com.","rrtype":"A","rdata":["198.51.100.3"]}]
        q = query(RDATA_IP, '198.51.100.3')
        self.run_query_rdata_always_array(q, expect)

    def test_rdata_always_array_query_rrdata_ipv6(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"www.example.com.","rrtype":"AAAA","rdata":["2001:db8::1"]}]
        q = query(RDATA_IP, '2001:db8::1')
        self.run_query_rdata_always_array(q, expect)

    def test_rdata_always_array_query_rrdata_name_mx(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"MX","rdata":["10 mail.example.com."]}]
        q = query(RDATA_NAME, 'mail.example.com')
        self.run_query_rdata_always_array(q, expect)

    def test_rdata_always_array_query_rrdata_name_ns(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"NS","rdata":["ns1.example.com."]}]
        q = query(RDATA_NAME, 'ns1.example.com')
        self.run_query_rdata_always_array(q, expect)

    def test_rdata_always_array_query_rrdata_name_wc(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"NS","rdata":["ns1.example.com."]},
                  {"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"NS","rdata":["ns2.example.com."]},
                  {"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"_ldap._tcp.example.com.","rrtype":"SRV","rdata":["10 1 389 ldap.example.com."]},
                  {"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"MX","rdata":["10 mail.example.com."]},
                  {"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"MX","rdata":["20 mail2.example.com."]},
                  {"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"SOA","rdata":["hidden-master.example.com. hostmaster.example.com. 2018032701 30 30 86400 300"]},
                  {"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"_wildcard_.example.com.","rrtype":"NS","rdata":["foo1.example.com."]},
                  {"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"_WILDCARD_.example.com.","rrtype":"NS","rdata":["foo2.example.com."]}]
        q = query(RDATA_NAME, '*.example.com')
        self.run_query_rdata_always_array(q, expect)

    def test_rdata_always_array_query_rrdata_name_soa(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"SOA","rdata":["hidden-master.example.com. hostmaster.example.com. 2018032701 30 30 86400 300"]}]
        q = query(RDATA_NAME, 'hidden-master.example.com', rrtype='SOA')
        self.run_query_rdata_always_array(q, expect)

    def test_rdata_always_array_query_rrdata_name_soa_wc(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"example.com.","rrtype":"SOA","rdata":["hidden-master.example.com. hostmaster.example.com. 2018032701 30 30 86400 300"]}]
        q = query(RDATA_NAME, '*.example.com', rrtype='SOA')
        self.run_query_rdata_always_array(q, expect)

    def test_rdata_always_array_query_rrdata_name_ldap(self):
        expect = [{"count":1,"time_first":1522147408,"time_last":1522147408,"rrname":"_ldap._tcp.example.com.","rrtype":"SRV","rdata":["10 1 389 ldap.example.com."]}]
        q = query(RDATA_NAME, 'ldap.example.com')
        self.run_query_rdata_always_array(q, expect)

    def test_formatter_json_rfc3339(self):
        expect = [{"count":1,"time_first":"2018-03-27T10:43:28Z","time_last":"2018-03-27T10:43:28Z","rrname":"example.com.","rrtype":"SOA","rdata":"hidden-master.example.com. hostmaster.example.com. 2018032701 30 30 86400 300"}]
        q = query(RDATA_NAME, '*.example.com', rrtype='SOA')
        self.run_query_rfc3339_time(q, expect)

    def run_query_fmt_dict(self, q, expect):
        gotsomething = False
        for i in self.r.query(q):
            gotsomething = True
            assert expect == i.to_fmt_dict(), \
                "expecting:\n    {}\ngot: {}".format(expect, i.to_fmt_dict())
        if expect == {}:
            assert gotsomething == False, "Query results not expected"
        else:
            assert gotsomething, "Query returned no results"

    def test_formatter_fmt_dict(self):
        expect = {'rrname': 'example.com.', 'rrtype': 'SOA', 'count': 1, 'time_first': 1522147408, 'time_last': 1522147408, 'rdata': ['hidden-master.example.com. hostmaster.example.com. 2018032701 30 30 86400 300']}
        q = query(RDATA_NAME, '*.example.com', rrtype='SOA')
        self.run_query_fmt_dict(q, expect)

    def run_query_text(self, q, expect):
        gotsomething = False
        for i in self.r.query(q):
            gotsomething = True
            assert expect == i.to_text(), \
                "expecting:\n    '{}'\ngot: '{}'".format(expect, i.to_text())
        if expect != "":
            assert gotsomething, "Query returned no results"
        else:
            assert gotsomething == False, "Query results not expected"

    def test_formatter_text(self):
        expect = "example.com. IN SOA hidden-master.example.com. hostmaster.example.com. 2018032701 30 30 86400 300\n"
        q = query(RDATA_NAME, '*.example.com', rrtype='SOA')
        self.run_query_text(q, expect)

    def test_query_casesensitive(self):
        expect1 = {'rrname': 'example.com.', 'rrtype': 'SOA', 'count': 1, 'time_first': 1522147408, 'time_last': 1522147408, 'rdata': ['hidden-master.example.com. hostmaster.example.com. 2018032701 30 30 86400 300']}
        expect2 = {}
        expect3 = {'rrname': '_wildcard_.example.com.', 'rrtype': 'NS', 'count': 1, 'time_first': 1522147408, 'time_last': 1522147408, 'rdata': ['foo1.example.com.'], 'bailiwick': 'example.com.'}
        expect4 = {'rrname': '_WILDCARD_.example.com.', 'rrtype': 'NS', 'count': 1, 'time_first': 1522147408, 'time_last': 1522147408, 'rdata': ['foo2.example.com.'], 'bailiwick': 'example.com.'}
        q1 = query(RDATA_NAME, '*.EXAMPLE.COM', rrtype='SOA', case_sensitive=False)
        q2 = query(RDATA_NAME, '*.EXAMPLE.COM', rrtype='SOA', case_sensitive=True)
        q3 = query(RRSET, '_WILDCARD_.example.com', rrtype='NS', case_sensitive=False)
        q4 = query(RRSET, '_WILDCARD_.example.com', rrtype='NS', case_sensitive=True)
        self.run_query_fmt_dict(q1, expect1)
        self.run_query_fmt_dict(q2, expect2)
        self.run_query_fmt_dict(q3, expect3)
        self.run_query_fmt_dict(q4, expect4)

if __name__ == '__main__':
    unittest.main()
