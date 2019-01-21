dnstable: Python bindings for the dnstable library
--------------------------------------------------

`pydnstable` is a Python wrapper for [dnstable](https://github.com/farsightsec/dnstable).


Usage
-----

See ```tests/test.py``` for other query examples. Note that you *must* pass a fileset to ```reader()```

    >>> from dnstable import *
    >>> r = reader("test-dns.fileset")
    >>> q = query(RRSET, 'www.example.com')
    >>> for i in r.query(q): print(i)
    ...
    ;;  bailiwick: example.com.
    ;;      count: 1
    ;; first seen: 2018-03-27 10:43:28 -0000
    ;;  last seen: 2018-03-27 10:43:28 -0000
    www.example.com. IN A 198.51.100.3
    www.example.com. IN A 198.51.100.4
    
    ;;  bailiwick: example.com.
    ;;      count: 1
    ;; first seen: 2018-03-27 10:43:28 -0000
    ;;  last seen: 2018-03-27 10:43:28 -0000
    www.example.com. IN AAAA 2001:db8::1
    www.example.com. IN AAAA 2001:db8::2

