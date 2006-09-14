Summary: Enhanced WHOIS client
Name: whois
Version: 4.7.16
Release: 1
License: GPL
Vendor: Marco d'Itri <md@linux.it>
Group: Applications/Internet
Source: http://ftp.debian.org/debian/pool/main/w/whois/whois_%{version}.tar.gz
BuildRoot: /var/tmp/%{name}-root
Prefix: /usr

%description
This is a new whois (RFC 954) client rewritten from scratch.
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

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(-,root,root)
%{prefix}/bin/whois
%doc %{prefix}/share/man/man1/whois.1.gz
%lang(de) %{prefix}/share/locale/de/LC_MESSAGES/whois.mo
%lang(el) %{prefix}/share/locale/el/LC_MESSAGES/whois.mo
%lang(es) %{prefix}/share/locale/es/LC_MESSAGES/whois.mo
%lang(fr) %{prefix}/share/locale/fr/LC_MESSAGES/whois.mo
%lang(it) %{prefix}/share/locale/it/LC_MESSAGES/whois.mo
%lang(no) %{prefix}/share/locale/no/LC_MESSAGES/whois.mo
%lang(pl) %{prefix}/share/locale/pl/LC_MESSAGES/whois.mo

%changelog
* Sun Jul 13 2003 Paul Mundt <lethal@linux-sh.org>
- Updated spec for 4.6.6, fixed up doc/lang references.
* Fri Feb 23 2001 Oren Tirosh <oren@hishome.net>
- Initial spec based on skelgnu.spec                  

