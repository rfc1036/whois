Summary: Enhanced WHOIS client
Name: whois
Version: 4.6.0
Release: 1
License: GPL
Vendor: Marco d'Itri <md@linux.it>
Group: Applications/Internet
Source: http://www.linux.it/~md/software/whois_%{version}.tar.gz
BuildRoot: /var/tmp/%{name}-root
Prefix: /usr

%description
This is a new whois (RFC 954) client rewritten from scratch by me.
It is derived from and compatible with the usual BSD and RIPE whois(1)
programs.
It is intelligent and can automatically select the appropriate whois
server for most queries.

%prep
%setup

%build
make OPTS="$RPM_OPT_FLAGS" 

%install
rm -rf ${RPM_BUILD_ROOT}
mkdir -p ${RPM_BUILD_ROOT}/usr/bin
mkdir -p ${RPM_BUILD_ROOT}%{_mandir}/man1
make install BASEDIR=${RPM_BUILD_ROOT} prefix=%{prefix}/
gzip ${RPM_BUILD_ROOT}%{_mandir}/man?/*

find $RPM_BUILD_ROOT ! -type d | sed "s@^$RPM_BUILD_ROOT@@g" > %{name}-filelist

%clean
rm -rf ${RPM_BUILD_ROOT}

%files -f %{name}-filelist
%defattr(-,root,root)
%doc [A-Z][A-Z]*

%changelog
* Fri Feb 23 2001 Oren Tirosh <oren@hishome.net>
- Initial spec based on skelgnu.spec                  

