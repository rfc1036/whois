prefix = /usr

ifdef DESTDIR
BASEDIR := $(DESTDIR)
endif

CFLAGS ?= -g -O2

PKG_CONFIG ?= pkg-config
PERL ?= perl
INSTALL ?= install

whois_OBJECTS := whois.o utils.o
mkpasswd_OBJECTS := mkpasswd.o utils.o

##############################################################################
# Solaris
#whois_LDADD += -lnsl -lsocket -liconv

# FreeBSD
#whois_LDADD += -liconv
#LIBS += -L/usr/local/lib -lintl
#DEFS += -I/usr/local/include

# OS/2 EMX
#whois_LDADD += -lsocket
#LDFLAGS += -Zexe -Dstrncasecmp=strnicmp

# OS X
#whois_LDADD += -liconv

ifdef CONFIG_FILE
DEFS += -DCONFIG_FILE=\"$(CONFIG_FILE)\"
endif

ifdef LOCALEDIR
DEFS += -DLOCALEDIR=\"$(BASEDIR)$(prefix)/share/locale\"
endif

# libidn support has been autodetected since 5.2.18
ifdef HAVE_LIBIDN
$(error Please fix your build system to stop defining HAVE_LIBIDN!)
endif

ifeq ($(shell $(PKG_CONFIG) --exists 'libidn2 >= 2.0.3' || echo NO),)
whois_LDADD += $(shell $(PKG_CONFIG) --libs libidn2)
DEFS += -DHAVE_LIBIDN2 $(shell $(PKG_CONFIG) --cflags libidn2)
else ifeq ($(shell $(PKG_CONFIG) --exists 'libidn' || echo NO),)
whois_LDADD += $(shell $(PKG_CONFIG) --libs libidn)
DEFS += -DHAVE_LIBIDN $(shell $(PKG_CONFIG) --cflags libidn)
endif

ifdef HAVE_ICONV
whois_OBJECTS += simple_recode.o
DEFS += -DHAVE_ICONV
endif

ifeq ($(shell $(PKG_CONFIG) --exists 'libxcrypt >= 4.1' || echo NO),)
DEFS += -DHAVE_CRYPT_H -DHAVE_LINUX_CRYPT_GENSALT $(shell $(PKG_CONFIG) --cflags libcrypt)
mkpasswd_LDADD += $(shell $(PKG_CONFIG) --libs libcrypt)
else ifdef HAVE_XCRYPT
DEFS += -DHAVE_XCRYPT_H -DHAVE_LINUX_CRYPT_GENSALT
mkpasswd_LDADD += -lxcrypt
else ifdef HAVE_LIBOWCRYPT
# owl and openSUSE have crypt_gensalt(3) in libowcrypt
DEFS += -DHAVE_CRYPT_H -DHAVE_LINUX_CRYPT_GENSALT -D_OW_SOURCE
mkpasswd_LDADD += -lcrypt -lowcrypt
else
mkpasswd_LDADD += -lcrypt
endif

CPPFLAGS += $(DEFS) $(INCLUDES)

BASHCOMPDIR ?= $(shell $(PKG_CONFIG) --variable=completionsdir bash-completion 2>/dev/null || echo /etc/bash_completion.d)

##############################################################################
all: Makefile.depend whois mkpasswd pos

##############################################################################
%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

whois: $(whois_OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(whois_LDADD) $(LIBS)

mkpasswd: $(mkpasswd_OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(mkpasswd_LDADD) $(LIBS)

##############################################################################
version.h: debian/changelog make_version_h.pl
	$(PERL) make_version_h.pl $< > $@

as_del.h: as_del_list make_as_del.pl
	$(PERL) make_as_del.pl < $< > $@

as32_del.h: as32_del_list make_as32_del.pl
	$(PERL) make_as32_del.pl < $< > $@

ip_del.h: ip_del_list make_ip_del.pl
	$(PERL) make_ip_del.pl < $< > $@

ip6_del.h: ip6_del_list make_ip6_del.pl
	$(PERL) make_ip6_del.pl < $< > $@

new_gtlds.h: new_gtlds_list make_new_gtlds.pl
	$(PERL) make_new_gtlds.pl < $< > $@

nic_handles.h: nic_handles_list make_nic_handles.pl
	$(PERL) make_nic_handles.pl < $< > $@

tld_serv.h: tld_serv_list make_tld_serv.pl
	$(PERL) make_tld_serv.pl < $< > $@

servers_charset.h: servers_charset_list make_servers_charset.pl
	$(PERL) make_servers_charset.pl < $< > $@

##############################################################################
afl:
	-rm -f Makefile.depend
	DEFS=-DAFL_MODE=1 AFL_HARDEN=1 $(MAKE) whois CC=afl-gcc HAVE_ICONV=1

afl-run:
	nice afl-fuzz -i ../afl_in -o ../afl_out -- ./whois

##############################################################################
install: install-whois install-mkpasswd install-pos install-bashcomp

install-whois: whois
	$(INSTALL) -d $(BASEDIR)$(prefix)/bin/
	$(INSTALL) -d $(BASEDIR)$(prefix)/share/man/man1/
	$(INSTALL) -d $(BASEDIR)$(prefix)/share/man/man5/
	$(INSTALL) -m 0755 whois $(BASEDIR)$(prefix)/bin/
	$(INSTALL) -m 0644 whois.1 $(BASEDIR)$(prefix)/share/man/man1/
	$(INSTALL) -m 0644 whois.conf.5 $(BASEDIR)$(prefix)/share/man/man5/

install-mkpasswd: mkpasswd
	$(INSTALL) -d $(BASEDIR)$(prefix)/bin/
	$(INSTALL) -d $(BASEDIR)$(prefix)/share/man/man1/
	$(INSTALL) -m 0755 mkpasswd $(BASEDIR)$(prefix)/bin/
	$(INSTALL) -m 0644 mkpasswd.1 $(BASEDIR)$(prefix)/share/man/man1/

install-pos:
	cd po && $(MAKE) install

install-bashcomp:
	$(INSTALL) -d $(BASEDIR)$(BASHCOMPDIR)
	$(INSTALL) -m 0644 mkpasswd.bash $(BASEDIR)$(BASHCOMPDIR)/mkpasswd
	$(INSTALL) -m 0644 whois.bash $(BASEDIR)$(BASHCOMPDIR)/whois

distclean: clean
	rm -f version.h po/whois.pot

clean:
	rm -f Makefile.depend as_del.h as32_del.h ip_del.h ip6_del.h \
		new_gtlds.h tld_serv.h servers_charset.h *.o whois mkpasswd
	rm -f po/*.mo

pos:
	cd po && $(MAKE)

depend: Makefile.depend
Makefile.depend:
	$(CC) $(CPPFLAGS) $(CFLAGS) -MM -MG *.c > $@

-include Makefile.depend

.DELETE_ON_ERROR:
