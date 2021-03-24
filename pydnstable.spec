Name:           python-pydnstable
Version:        0.7.2
Release:        1%{?dist}
Summary:        passive DNS encoding format library (Python bindings)

License:        Apache-2.0
URL:            https://github.com/farsightsec/pydnstable/
Source0:        https://dl.farsightsecurity.com/dist/pydnstable/pydnstable-%{version}.tar.gz

#BuildArch:
BuildRequires:  python-devel dnstable-devel Cython >= 0.25.2
BuildRequires:  python3-devel python36-Cython
Requires:       dnstable mtbl

%description
dnstable implements an encoding format for passive DNS data.  It stores
key-value records in Sorted String Table (SSTable) files using MTBL.

This package contains the Python extension module for libdnstable.


%prep
%setup -q -n pydnstable-%{version}


%build
# remove cython-generated code if is there
rm -f dnstable.c
# Remove CFLAGS=... for noarch packages (unneeded)
CFLAGS="$RPM_OPT_FLAGS" %{__python} setup.py build
%py3_build

%install
rm -rf $RPM_BUILD_ROOT
%{__python} setup.py install -O1 --skip-build --root $RPM_BUILD_ROOT
%py3_install

%files
%doc
# For arch-specific packages: sitearch
%{python_sitearch}/*

%package -n python3-pydnstable
Summary:        passive DNS encoding format library (Python3 bindings)

%description -n python3-pydnstable
dnstable implements an encoding format for passive DNS data.  It stores
key-value records in Sorted String Table (SSTable) files using MTBL.

This package contains the Python 3 extension module for libdnstable.

%files -n python3-pydnstable
%doc
%{python3_sitearch}/*


%changelog
