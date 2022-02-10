Name:           python3-pydnstable
Version:        0.7.2
Release:        2%{?dist}
Summary:        passive DNS encoding format library (Python3 bindings)

License:        Apache-2.0
URL:            https://github.com/farsightsec/pydnstable/
Source0:        https://dl.farsightsecurity.com/dist/pydnstable/pydnstable-%{version}.tar.gz

#BuildArch:
BuildRequires:  dnstable-devel
BuildRequires:  python3-devel python36-Cython
Requires:       dnstable mtbl

%description
dnstable implements an encoding format for passive DNS data.  It stores
key-value records in Sorted String Table (SSTable) files using MTBL.

This package contains the Python 3 extension module for libdnstable.


%prep
%setup -q -n pydnstable-%{version}


%build
# remove cython-generated code if is there
rm -f dnstable.c
%py3_build


%install
rm -rf $RPM_BUILD_ROOT
%py3_install


%files
%doc
# For arch-specific packages: sitearch
%{python3_sitearch}/*


%changelog
