AUTOMAKE_OPTIONS = ../ansi2knr

bin_PROGRAMS = @BUILD_WHOIS@

EXTRA_PROGRAMS = whois

whois_SOURCES = whois.c

whois_DEPENDENCIES = as_del_list ip_del_list tld_serv_list

CLEANFILES = as_del.h ip_del.h tld_serv.h

as_del.h: as_del_list make_as_del.pl
	perl make_as_del.pl < as_del_list > as_del.h

ip_del.h: ip_del_list make_ip_del.pl
	perl make_ip_del.pl < ip_del_list > ip_del.h

tld_serv.h: tld_serv_list make_tld_serv.pl
	perl make_tld_serv.pl < tld_serv_list > tld_serv.h

