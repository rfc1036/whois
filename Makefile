prefix = /usr/local

CFLAGS = -g -O2

PERL = perl

# Solaris
#whois_LDADD += -lnsl -lsocket

# FreeBSD
#LIBS += -L/usr/local/lib -lintl
#INCLUDES += -I/usr/local/include

# OS/2 EMX
#whois_LDADD += -lsocket
#LDFLAGS += -Zexe -Dstrncasecmp=strnicmp

ifdef CONFIG_FILE
DEFS += -DCONFIG_FILE=\"$(CONFIG_FILE)\"
endif

ifdef HAVE_LIBIDN
whois_LDADD += -lidn
DEFS += -DHAVE_LIBIDN
endif

ifdef HAVE_XCRYPT
mkpasswd_LDADD += -lxcrypt
DEFS += -DHAVE_XCRYPT
else
mkpasswd_LDADD += -lcrypt
endif

all: Makefile.depend whois mkpasswd #pos

whois_OBJECTS := whois.o utils.o
mkpasswd_OBJECTS := mkpasswd.o utils.o

##############################################################################
%.o: %.c
	$(CC) $(DEFS) $(INCLUDES) $(CFLAGS) -c $<

whois: $(whois_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(whois_LDADD) $(LIBS)

mkpasswd: $(mkpasswd_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(mkpasswd_LDADD) $(LIBS)

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
install: install-whois install-mkpasswd install-pos

install-whois: whois
	install -d $(BASEDIR)$(prefix)/bin/
	install -d $(BASEDIR)$(prefix)/share/man/man1/
	install -m 0755 whois $(BASEDIR)$(prefix)/bin/
	install -m 0644 whois.1 $(BASEDIR)$(prefix)/share/man/man1/

install-mkpasswd: mkpasswd
	install -d $(BASEDIR)$(prefix)/bin/
	install -d $(BASEDIR)$(prefix)/share/man/man1/
	install -m 0755 mkpasswd $(BASEDIR)$(prefix)/bin/
	install -m 0644 mkpasswd.1 $(BASEDIR)$(prefix)/share/man/man1/

install-pos:
	cd po && $(MAKE) $@

distclean: clean
	rm -f po/whois.pot

clean:
	rm -f Makefile.depend as_del.h ip_del.h ip6_del.h tld_serv.h \
		*.o whois mkpasswd
	rm -f po/*.mo

pos:
	cd po && $(MAKE)

depend: Makefile.depend
Makefile.depend:
	$(CC) $(DEFS) $(INCLUDES) $(CFLAGS) -MM -MG *.c > $@

-include Makefile.depend
