OPTS=-O2

all: whois #pos

whois: whois.c whois.h config.h data.h ip_del.h tld_serv.h
	$(CC) $(OPTS) whois.c -o whois

mkpasswd:
	$(CC) $(OPTS) mkpasswd.c -o mkpasswd -lcrypt

ip_del.h: ip_del_list make_ip_del.pl
	./make_ip_del.pl < ip_del_list > ip_del.h

tld_serv.h: tld_serv_list make_tld_serv.pl
	./make_tld_serv.pl < tld_serv_list > tld_serv.h

distclean: clean
	rm -f po/whois.pot

clean:
	rm -f tld_serv.h ip_del.h whois mkpasswd
	rm -f po/*.mo

test:
	open -- sh -c "while nc -l -p 43 127.0.0.1; do echo END; done"

pos:
	cd po && $(MAKE)

