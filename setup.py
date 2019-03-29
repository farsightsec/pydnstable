#!/usr/bin/env python

NAME = 'pydnstable'
VERSION = '0.6.1'

import os
from distutils.core import setup
from distutils.extension import Extension
from distutils.command.clean import clean


class Cleaner(clean):
        def run(self):
            clean.run(self)
            for i in ["dnstable.c"]:
                if os.path.isfile(i):
                    print "Cleaning ", i
                    os.unlink(i)

def pkgconfig(*packages, **kw):
    import subprocess
    flag_map = {
            '-I': 'include_dirs',
            '-L': 'library_dirs',
            '-l': 'libraries'
    }
    pkg_config_cmd = 'pkg-config --cflags --libs "%s"' % ' '.join(packages)
    for token in subprocess.check_output(pkg_config_cmd, shell=True).split():
        flag = token[:2]
        arg = token[2:]
        if flag in flag_map:
            kw.setdefault(flag_map[flag], []).append(arg)
    return kw

try:
    from Cython.Distutils import build_ext
    setup(
        name = NAME,
        version = VERSION,
        ext_modules = [ Extension('dnstable', ['dnstable.pyx'], **pkgconfig('libdnstable >= 0.9.0')) ],
        cmdclass = {'build_ext': build_ext, 'clean': Cleaner }
    )
except ImportError:
    import os
    if os.path.isfile('dnstable.c'):
        setup(
            name = NAME,
            version = VERSION,
            ext_modules = [ Extension('dnstable', ['dnstable.c'], **pkgconfig('libdnstable >= 0.9.0')) ],
        )
    else:
        raise
