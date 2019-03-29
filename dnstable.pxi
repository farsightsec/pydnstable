#cython: embedsignature=True
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

cimport cython
from libcpp cimport bool
from cpython.string cimport *
from libc.stddef cimport *
from libc.stdint cimport *
from libc.stdlib cimport *
from libc.string cimport *

cdef extern from "sys/time.h" nogil:
    ctypedef int time_t
    cdef struct timespec:
        time_t tv_sec
        long   tv_nsec

cdef extern from "dnstable.h" nogil:
    ctypedef enum dnstable_res:
        dnstable_res_failure
        dnstable_res_success
        dnstable_res_timeout

    ctypedef enum dnstable_entry_type:
        DNSTABLE_ENTRY_TYPE_RRSET
        DNSTABLE_ENTRY_TYPE_RRSET_NAME_FWD
        DNSTABLE_ENTRY_TYPE_RDATA
        DNSTABLE_ENTRY_TYPE_RDATA_NAME_REV

    ctypedef enum dnstable_query_type:
        DNSTABLE_QUERY_TYPE_RRSET
        DNSTABLE_QUERY_TYPE_RDATA_NAME
        DNSTABLE_QUERY_TYPE_RDATA_IP
        DNSTABLE_QUERY_TYPE_RDATA_RAW

    ctypedef enum dnstable_filter_parameter_type:
        DNSTABLE_FILTER_PARAMETER_TIME_FIRST_BEFORE
        DNSTABLE_FILTER_PARAMETER_TIME_FIRST_AFTER
        DNSTABLE_FILTER_PARAMETER_TIME_LAST_BEFORE
        DNSTABLE_FILTER_PARAMETER_TIME_LAST_AFTER

    struct dnstable_entry:
        pass
    struct dnstable_iter:
        pass
    struct dnstable_query:
        pass
    struct dnstable_reader:
        pass

    # entry
    void dnstable_entry_destroy(dnstable_entry **)
    void dnstable_entry_set_iszone(dnstable_entry *, bool)
    dnstable_entry_type dnstable_entry_get_type(dnstable_entry *)
    dnstable_res dnstable_entry_get_rrname(dnstable_entry *, uint8_t **, size_t *)
    dnstable_res dnstable_entry_get_rrtype(dnstable_entry *, uint16_t *)
    dnstable_res dnstable_entry_get_bailiwick(dnstable_entry *, uint8_t **, size_t *)
    dnstable_res dnstable_entry_get_num_rdata(dnstable_entry *, size_t *)
    dnstable_res dnstable_entry_get_rdata(dnstable_entry *, size_t, uint8_t **, size_t *)
    dnstable_res dnstable_entry_get_time_first(dnstable_entry *, uint64_t *)
    dnstable_res dnstable_entry_get_time_last(dnstable_entry *, uint64_t *)
    dnstable_res dnstable_entry_get_count(dnstable_entry *, uint64_t *)
    char * dnstable_entry_to_json(dnstable_entry *)
    char * dnstable_entry_to_text(dnstable_entry *)

    # iter
    void dnstable_iter_destroy(dnstable_iter **)
    dnstable_res dnstable_iter_next(dnstable_iter *, dnstable_entry **)

    # query
    dnstable_query * dnstable_query_init(dnstable_query_type)
    void dnstable_query_destroy(dnstable_query **)
    char * dnstable_query_get_error(dnstable_query *)
    dnstable_res dnstable_query_set_data(dnstable_query *, char *)
    dnstable_res dnstable_query_set_rrtype(dnstable_query *, char *)
    dnstable_res dnstable_query_set_skip(dnstable_query *, uint64_t)
    dnstable_res dnstable_query_set_aggregated(dnstable_query *, bool)
    bool dnstable_query_is_aggregated(const dnstable_query *)
    dnstable_res dnstable_query_set_bailiwick(dnstable_query *, char *)
    dnstable_res dnstable_query_set_timeout(dnstable_query *, timespec *)
    dnstable_res dnstable_query_set_filter_parameter(dnstable_query *, dnstable_filter_parameter_type, void *, size_t)

    # reader
    dnstable_reader * dnstable_reader_init_setfile(char *)
    void dnstable_reader_reload_setfile(dnstable_reader *)
    void dnstable_reader_destroy(dnstable_reader **)
    dnstable_iter * dnstable_reader_iter(dnstable_reader *)
    dnstable_iter * dnstable_reader_query(dnstable_reader *, dnstable_query *)
