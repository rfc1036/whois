INSTALL= /usr/bin/install -c
INSTALLNLSDIR=$(BASEDIR)/usr/share/locale

PACKAGE = whois

CATALOGS = it.mo no.mo

POTFILES=../whois.c

all: $(PACKAGE).pot $(CATALOGS)

$(PACKAGE).pot: $(POTFILES)
	xgettext --default-domain=$(PACKAGE) \
       	  --add-comments --keyword=_ --keyword=N_ $(POTFILES)
	if cmp -s $(PACKAGE).po $(PACKAGE).pot; then \
	  rm -f $(PACKAGE).po; \
	else \
	  mv $(PACKAGE).po $(PACKAGE).pot; \
	fi

update-po: $(PACKAGE).pot
	for cat in $(CATALOGS); do \
	  lang=`echo $$cat | sed 's/.mo$$//'`; \
	  mv $$lang.po $$lang.old.po; \
	  echo "$$lang:"; \
	  if msgmerge $$lang.old.po $(PACKAGE).pot -o $$lang.po; then \
	    rm -f $$lang.old.po; \
	  else \
    	    echo "msgmerge for $$cat failed!"; \
	    rm -f $$lang.po; mv $$lang.old.po $$lang.po; \
	  fi; \
	done

%.mo: %.po
	msgfmt --statistics --check --verbose --output-file=$@ $<

clean:
	rm -f *.mo

distclean: clean
	rm -f whois.pot

install: $(CATALOGS)
	for n in $(CATALOGS); do \
	    l=`basename $$n .mo`; \
	    $(INSTALL) -m 755 -d $(INSTALLNLSDIR)/$$l; \
	    $(INSTALL) -m 755 -d $(INSTALLNLSDIR)/$$l/LC_MESSAGES; \
	    $(INSTALL) -m 644 $$n $(INSTALLNLSDIR)/$$l/LC_MESSAGES/$(PACKAGE).mo; \
	done

