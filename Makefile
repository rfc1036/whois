prefix=/usr/local

OPTS=-O2

# Solaris
#LDFLAGS=-lnsl -lsocket

all: whois #pos

whois: whois.c whois.h config.h data.h as_del.h ip_del.h tld_serv.h
	$(CC) $(OPTS) whois.c -o whois $(LDFLAGS)

mkpasswd:
	$(CC) $(OPTS) mkpasswd.c -o mkpasswd -lcrypt

as_del.h: as_del_list make_as_del.pl
	perl make_as_del.pl < as_del_list > as_del.h

ip_del.h: ip_del_list make_ip_del.pl
	perl make_ip_del.pl < ip_del_list > ip_del.h

tld_serv.h: tld_serv_list make_tld_serv.pl
	perl make_tld_serv.pl < tld_serv_list > tld_serv.h

install: whois
	install --strip -m 0755 whois $(BASEDIR)$(prefix)/bin/
	install --strip -m 0644 whois.1 $(BASEDIR)$(prefix)/man/man1/
	cd po && $(MAKE) $@


distclean: clean
	rm -f po/whois.pot

clean:
	rm -f as_del.h ip_del.h tld_serv.h whois mkpasswd
	rm -f po/*.mo

test:
	open -- sh -c "while nc -l -p 43 127.0.0.1; do echo END; done"

pos:
	cd po && $(MAKE)

