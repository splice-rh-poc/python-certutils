# python-certutils package ----------------------------------------------------
Name:		python-certutils
Version:	0.7
Release:	1%{?dist}
Summary:	Common code for manipulating X.509 certificates

Group:		Development/Languages
License:	GPLv2+
URL:        https://github.com/splice/python-certutils
Source0:	%{name}-%{version}.tar.gz

BuildRequires:  python-setuptools
BuildRequires:	    python2-devel


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
* Thu Oct 18 2012 John Matthews <jmatthews@redhat.com> 0.7-1
- Fixed parsing of a certs subject to use m2crypto and not our own code, now
  able to parse subjects with more than just CN set. (jmatthews@redhat.com)
- SELinux script currently only needed for development setup, applies 'lib_t'
  to src directory (jmatthews@redhat.com)

* Tue Oct 16 2012 James Slagle <jslagle@redhat.com> 0.6-1
- Allow any subject attribute to be passed to the request generate method
  (jslagle@redhat.com)
- This should be a BuildRequires (jslagle@redhat.com)

* Tue Oct 16 2012 James Slagle <jslagle@redhat.com> 0.5-1
- Fix default parameter value (jslagle@redhat.com)

* Mon Oct 15 2012 James Slagle <jslagle@redhat.com> 0.4-1
- Updated gitignore (jslagle@redhat.com)
- Updates (jslagle@redhat.com)

* Mon Oct 15 2012 James Slagle <jslagle@redhat.com> 0.3-1
- Package egg files (jslagle@redhat.com)
- Add setup.py (jslagle@redhat.com)

* Mon Oct 15 2012 James Slagle <jslagle@redhat.com> 0.2-1
- new package built with tito

