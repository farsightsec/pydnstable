Name:           python3-pydnstable
Version:        0.8.1
Release:        1%{?dist}
Summary:        passive DNS encoding format library (Python3 bindings)

License:        Apache-2.0
URL:            https://github.com/farsightsec/pydnstable
Source0:        pydnstable-%{version}.tar.gz

BuildRequires:  dnstable-devel
BuildRequires:  python3-devel
BuildRequires:  python3-Cython
BuildRequires:  python3-setuptools
BuildRequires:  pkg-config
Requires:       dnstable mtbl

%description
dnstable implements an encoding format for passive DNS data. It stores
key-value records in Sorted String Table (SSTable) files using MTBL.

This package contains the Python 3 extension module for libdnstable.

%prep
%setup -q -n pydnstable-%{version}

%build
rm -f dnstable.c
%py3_build

%install
%py3_install

%files
%license COPYRIGHT LICENSE
%doc README.md
%{python3_sitearch}/dnstable*.so
%{python3_sitearch}/pydnstable-%{version}-*.egg-info

%changelog
* Mon Aug 18 2026 Allan LeSage <alesage@domaintools.com> - 0.8.1-1
- Fix build with Cython 3.X
- Modernize packaging: add pyproject.toml, clean up spec
