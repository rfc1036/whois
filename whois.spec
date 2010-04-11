Summary: Enhanced WHOIS client
Name: whois
Version: 5.0.2
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
make CFLAGS="$RPM_OPT_FLAGS" HAVE_LIBIDN=1 HAVE_ICONV=1

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
%{prefix}/bin/mkpasswd
%doc %{prefix}/share/man/man1/whois.1.gz
%doc %{prefix}/share/man/man1/mkpasswd.1.gz
%lang(cs) %{prefix}/share/locale/cs/LC_MESSAGES/whois.mo
%lang(de) %{prefix}/share/locale/de/LC_MESSAGES/whois.mo
%lang(el) %{prefix}/share/locale/el/LC_MESSAGES/whois.mo
%lang(es) %{prefix}/share/locale/es/LC_MESSAGES/whois.mo
%lang(eu) %{prefix}/share/locale/eu/LC_MESSAGES/whois.mo
%lang(fr) %{prefix}/share/locale/fr/LC_MESSAGES/whois.mo
%lang(it) %{prefix}/share/locale/it/LC_MESSAGES/whois.mo
%lang(ja) %{prefix}/share/locale/ja/LC_MESSAGES/whois.mo
%lang(no) %{prefix}/share/locale/no/LC_MESSAGES/whois.mo
%lang(pl) %{prefix}/share/locale/pl/LC_MESSAGES/whois.mo
%lang(pt_BR) %{prefix}/share/locale/pt_BR/LC_MESSAGES/whois.mo
%lang(ru) %{prefix}/share/locale/ru/LC_MESSAGES/whois.mo

%changelog
* Sun Jul 13 2003 Paul Mundt <lethal@linux-sh.org>
- Updated spec for 4.6.6, fixed up doc/lang references.
* Fri Feb 23 2001 Oren Tirosh <oren@hishome.net>
- Initial spec based on skelgnu.spec                  

