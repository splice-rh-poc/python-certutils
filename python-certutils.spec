# python-certutils package ----------------------------------------------------
Name:		python-certutils
Version:	0.4
Release:	1%{?dist}
Summary:	Common code for manipulating X.509 certificates

Group:		Development/Languages
License:	GPLv2+
URL:        https://github.com/splice/python-certutils
Source0:	%{name}-%{version}.tar.gz

BuildRequires:  python-setuptools
Requires:	    python2-devel


%description
Common code for manipulating X.509 certificates


%prep
%setup -q


%build
pushd src
%{__python} setup.py build
popd


%install
rm -rf %{buildroot}
pushd src
%{__python} setup.py install -O1 --skip-build --root %{buildroot}
popd


%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%{python_sitelib}/certutils
%{python_sitelib}/python_certutils*


%changelog
* Mon Oct 15 2012 James Slagle <jslagle@redhat.com> 0.4-1
- Updated gitignore (jslagle@redhat.com)
- Updates (jslagle@redhat.com)

* Mon Oct 15 2012 James Slagle <jslagle@redhat.com> 0.3-1
- Package egg files (jslagle@redhat.com)
- Add setup.py (jslagle@redhat.com)

* Mon Oct 15 2012 James Slagle <jslagle@redhat.com> 0.2-1
- new package built with tito

