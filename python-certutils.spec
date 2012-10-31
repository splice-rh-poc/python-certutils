# python-certutils package ----------------------------------------------------
Name:		python-certutils
Version:	0.14
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
mkdir -p %{buildroot}/%{_sysconfdir}/splice/certs/
mkdir -p %{buildroot}/%{_bindir}

pushd src
%{__python} setup.py install -O1 --skip-build --root %{buildroot}
popd
cp -R etc/splice/certs/generate  %{buildroot}/%{_sysconfdir}/splice/certs/
cp bin/* %{buildroot}/%{_bindir}

%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%{python_sitelib}/certutils
%{python_sitelib}/python_certutils*
%{_sysconfdir}/splice/certs/generate
%{_bindir}



%changelog
* Wed Oct 31 2012 John Matthews <jmatthews@redhat.com> 0.14-1
- Update for parsing a cert when running with an unpatched m2crypto
  (jmatthews@redhat.com)

* Mon Oct 29 2012 John Matthews <jmatthews@redhat.com> 0.13-1
- Fix to create output directory when generating splice identity certs
  (jmatthews@redhat.com)

* Fri Oct 26 2012 John Matthews <jmatthews@redhat.com> 0.12-1
- Added script to generate a Splice Server identity certificate for testing
  (jmatthews@redhat.com)

* Fri Oct 26 2012 John Matthews <jmatthews@redhat.com> 0.11-1
- Update to comment out default Apache ssl settings (jmatthews@redhat.com)

* Fri Oct 26 2012 John Matthews <jmatthews@redhat.com> 0.10-1
- Changed names of generated certs to clearly call out they are for the HTTPS
  setup (jmatthews@redhat.com)

* Thu Oct 25 2012 John Matthews <jmatthews@redhat.com> 0.9-1
- Packaging updates for certificate generation files (jmatthews@redhat.com)

* Thu Oct 25 2012 John Matthews <jmatthews@redhat.com> 0.8-1
- Update for selinux rules in developer setup (jmatthews@redhat.com)
- Adding x509 certificate generation & configuration scripts - Will be able to
  create a new CA and Server Certificate for https connections - Configures
  apache through the splice.conf to use these generated certificates
  (jmatthews@redhat.com)
- Added a CertificateParseException and updated get_subject_pieces() to throw
  this when bad data is passed in (jmatthews@redhat.com)

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

