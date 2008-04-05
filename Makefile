prefix = /usr/local

OPTS := -O2

# Solaris
#whois_LDADD += -lnsl -lsocket

# FreeBSD
#LDFLAGS=-L/usr/local/lib -lgnugetopt -lintl
#CFLAGS=-I/usr/local/include

# OS/2 EMX
#LDFLAGS=-lsocket -Zexe -Dstrncasecmp=strnicmp

ifdef HAVE_LIBIDN
whois_LDADD += -lidn
CFLAGS += -DHAVE_LIBIDN
endif

ifdef HAVE_XCRYPT
mkpasswd_LDADD += -lxcrypt
CFLAGS += -DHAVE_XCRYPT
else
mkpasswd_LDADD += -lcrypt
endif

PERL := perl

all: Makefile.depend whois mkpasswd #pos

##############################################################################
%.o: %.c
	$(CC) $(CFLAGS) $(OPTS) -c $<

whois: whois.o utils.o
	$(CC) $(LDFLAGS) $(whois_LDADD) -o $@ $^

mkpasswd: mkpasswd.o utils.o
	$(CC) $(LDFLAGS) $(mkpasswd_LDADD) -o $@ $^

##############################################################################
as_del.h: as_del_list make_as_del.pl
	$(PERL) -w make_as_del.pl < as_del_list > $@

as32_del.h: as32_del_list make_as32_del.pl
	$(PERL) -w make_as32_del.pl < as32_del_list > $@

ip_del.h: ip_del_list make_ip_del.pl
	$(PERL) -w make_ip_del.pl < ip_del_list > $@

ip6_del.h: ip6_del_list make_ip6_del.pl
	$(PERL) -w make_ip6_del.pl < ip6_del_list > $@

tld_serv.h: tld_serv_list make_tld_serv.pl
	$(PERL) -w make_tld_serv.pl < tld_serv_list > $@

##############################################################################
install: whois
	install -d $(BASEDIR)$(prefix)/bin/
	install -d $(BASEDIR)$(prefix)/share/man/man1/
	install -m 0755 whois $(BASEDIR)$(prefix)/bin/
	install -m 0644 whois.1 $(BASEDIR)$(prefix)/share/man/man1/
	cd po && $(MAKE) $@

install-mkpasswd: mkpasswd
	install -d $(BASEDIR)$(prefix)/bin/
	install -d $(BASEDIR)$(prefix)/share/man/man1/
	install -m 0755 mkpasswd $(BASEDIR)$(prefix)/bin/
	install -m 0644 mkpasswd.1 $(BASEDIR)$(prefix)/share/man/man1/

distclean: clean
	rm -f po/whois.pot

clean:
	rm -f Makefile.depend as_del.h ip_del.h ip6_del.h tld_serv.h \
		*.o whois mkpasswd
	rm -f po/*.mo

test:
	open -- sh -c "while nc -l -p 43 127.0.0.1; do echo END; done"

gnu:
	tar czvvf gnu-whois.tgz Makefile* README *list *.h whois.*

pos:
	cd po && $(MAKE)

depend: Makefile.depend
Makefile.depend:
	$(CC) $(CFLAGS) -MM -MG *.c > $@

-include Makefile.depend
