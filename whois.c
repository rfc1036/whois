/*
 * Copyright 1999-2010 by Marco d'Itri <md@linux.it>.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* for AI_IDN */
#define _GNU_SOURCE

/* System library */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include "config.h"
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#endif
#ifdef HAVE_REGEXEC
#include <regex.h>
#endif
#ifdef HAVE_LIBIDN
#include <idna.h>
#endif
#ifdef HAVE_INET_PTON
#include <arpa/inet.h>
#endif

/* Application-specific */
#include "version.h"
#include "data.h"
#include "whois.h"
#include "utils.h"

#ifdef HAVE_ICONV
#include "simple_recode.h"
#else
#define recode_fputs(a, b) fputs(a, b)
#endif

/* hack */
#define malloc(s) NOFAIL(malloc(s))
#define realloc(p, s) NOFAIL(realloc(p, s))
#ifdef strdup
#undef strdup
#define strdup(s) NOFAIL(__strdup(s))
#else
#define strdup(s) NOFAIL(strdup(s))
#endif

/* Global variables */
int sockfd, verb = 0;

#ifdef ALWAYS_HIDE_DISCL
int hide_discl = HIDE_NOT_STARTED;
#else
int hide_discl = HIDE_DISABLED;
#endif

const char *client_tag = IDSTRING;

#ifdef HAVE_GETOPT_LONG
static const struct option longopts[] = {
    {"version",	no_argument,		NULL, 1  },
    {"verbose",	no_argument,		NULL, 2  },
    {"help",	no_argument,		NULL, 3  },
    {"server",	required_argument,	NULL, 'h'},
    {"host",	required_argument,	NULL, 'h'},
    {"port",	required_argument,	NULL, 'p'},
    {NULL,	0,			NULL, 0  }
};
#else
extern char *optarg;
extern int optind;
#endif

int main(int argc, char *argv[])
{
    int ch, nopar = 0, fstringlen = 64;
    const char *server = NULL, *port = NULL;
    char *qstring, *fstring;
    int ret;

#ifdef ENABLE_NLS
    setlocale(LC_ALL, "");
    bindtextdomain(NLS_CAT_NAME, LOCALEDIR);
    textdomain(NLS_CAT_NAME);
#endif

    fstring = malloc(fstringlen + 1);
    *fstring = '\0';

    /* prepend options from environment */
    argv = merge_args(getenv("WHOIS_OPTIONS"), argv, &argc);

    while ((ch = GETOPT_LONGISH(argc, argv,
		"abBcdFg:Gh:Hi:KlLmMp:q:rRs:t:T:v:V:x", longopts, 0)) > 0) {
	/* RIPE flags */
	if (strchr(ripeflags, ch)) {
	    if (strlen(fstring) + 3 > fstringlen) {
		fstringlen += 3;
		fstring = realloc(fstring, fstringlen + 1);
	    }
	    sprintf(fstring + strlen(fstring), "-%c ", ch);
	    continue;
	}
	if (strchr(ripeflagsp, ch)) {
	    int flaglen = 3 + strlen(optarg) + 1;
	    if (strlen(fstring) + flaglen > fstringlen) {
		fstringlen += flaglen;
		fstring = realloc(fstring, fstringlen + 1);
	    }
	    sprintf(fstring + strlen(fstring), "-%c %s ", ch, optarg);
	    if (ch == 't' || ch == 'v' || ch == 'q')
		nopar = 1;
	    continue;
	}
	/* program flags */
	switch (ch) {
	case 'h':
	    server = strdup(optarg);
	    break;
	case 'V':
	    client_tag = optarg;
	    break;
	case 'H':
	    hide_discl = HIDE_NOT_STARTED;	/* enable disclaimers hiding */
	    break;
	case 'p':
	    port = strdup(optarg);
	    break;
	case 3:
	    usage(EXIT_SUCCESS);
	case 2:
	    verb = 1;
	    break;
	case 1:
	    fprintf(stdout, _("Version %s.\n\nReport bugs to %s.\n"),
		    VERSION, "<md+whois@linux.it>");
	    exit(EXIT_SUCCESS);
	default:
	    usage(EXIT_FAILURE);
	}
    }
    argc -= optind;
    argv += optind;

    if (argc == 0 && !nopar)	/* there is no parameter */
	usage(EXIT_FAILURE);

    /* On some systems realloc only works on non-NULL buffers */
    /* I wish I could remember which ones they are... */
    qstring = malloc(64);
    *qstring = '\0';

    /* parse other parameters, if any */
    if (!nopar) {
	int qstringlen = 0;

	while (1) {
	    qstringlen += strlen(*argv) + 1;
	    qstring = realloc(qstring, qstringlen + 1);
	    strcat(qstring, *argv++);
	    if (argc == 1)
		break;
	    strcat(qstring, " ");
	    argc--;
	}
    }

    signal(SIGTERM, sighandler);
    signal(SIGINT, sighandler);
    signal(SIGALRM, alarm_handler);

    if (getenv("WHOIS_HIDE"))
	hide_discl = HIDE_NOT_STARTED;

    /* -v or -t has been used */
    if (!server && !*qstring)
	server = strdup("whois.ripe.net");

    if (*qstring) {
	char *tmp = normalize_domain(qstring);
	free(qstring);
	qstring = tmp;
    }

#ifdef CONFIG_FILE
    if (!server) {
	server = match_config_file(qstring);
	if (verb && server)
	    printf(_("Using server %s.\n"), server);
    }
#endif

    if (!server)
	server = guess_server(qstring);

    ret = handle_query(server, port, qstring, fstring);

    exit(ret);
}

/*
 * Server may be a server name from the command line, a server name got
 * from guess_server or an encoded command/message from guess_server.
 * This function has multiple memory leaks.
 */
int handle_query(const char *hserver, const char *hport,
	const char *query, const char *flags)
{
    char *server = NULL, *port = NULL;
    char *p, *query_string;

    if (hport) {
	server = strdup(hserver);
	port = strdup(hport);
    } else if (hserver[0] < ' ')
	server = strdup(hserver);
    else
	split_server_port(hserver, &server, &port);

    retry:
    switch (server[0]) {
	case 0:
	    if (!(server = getenv("WHOIS_SERVER")))
		server = strdup(DEFAULTSERVER);
	    break;
	case 1:
	    puts(_("This TLD has no whois server, but you can access the "
			"whois database at"));
	    puts(server + 1);
	    return 1;
	case 3:
	    puts(_("This TLD has no whois server."));
	    return 1;
	case 5:
	    puts(_("No whois server is known for this kind of object."));
	    return 1;
	case 6:
	    puts(_("Unknown AS number or IP network. Please upgrade this program."));
	    return 1;
	case 4:
	    if (verb)
		printf(_("Using server %s.\n"), server + 1);
	    sockfd = openconn(server + 1, NULL);
	    free(server);
	    server = query_crsnic(sockfd, query);
	    break;
	case 8:
	    if (verb)
		printf(_("Using server %s.\n"), "whois.afilias-grs.info");
	    sockfd = openconn("whois.afilias-grs.info", NULL);
	    free(server);
	    server = query_afilias(sockfd, query);
	    break;
	case 0x0A:
	    p = convert_6to4(query);
	    printf(_("\nQuerying for the IPv4 endpoint %s of a 6to4 IPv6 address.\n\n"), p);
	    free(server);
	    server = guess_server(p);
	    query = p;
	    goto retry;
	case 0x0B:
	    p = convert_teredo(query);
	    printf(_("\nQuerying for the IPv4 endpoint %s of a Teredo IPv6 address.\n\n"), p);
	    free(server);
	    server = guess_server(p);
	    query = p;
	    goto retry;
	case 0x0C:
	    p = convert_inaddr(query);
	    free(server);
	    server = guess_server(p);
	    free(p);
	    goto retry;
	default:
	    break;
    }

    if (!server)
	return 1;

    query_string = queryformat(server, flags, query);
    if (verb) {
	printf(_("Using server %s.\n"), server);
	printf(_("Query string: \"%s\"\n\n"), query_string);
    }

    sockfd = openconn(server, port);

    server = do_query(sockfd, query_string);
    free(query_string);

    /* recursion is fun */
    if (server && !strchr(query, ' ')) {
	printf(_("\n\nFound a referral to %s.\n\n"), server);
	handle_query(server, NULL, query, flags);
    }

    return 0;
}

#ifdef CONFIG_FILE
const char *match_config_file(const char *s)
{
    FILE *fp;
    char buf[512];
    static const char delim[] = " \t";

    if ((fp = fopen(CONFIG_FILE, "r")) == NULL) {
	if (errno != ENOENT)
	    err_sys("Cannot open " CONFIG_FILE);
	return NULL;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
	char *p;
	const char *pattern, *server;
#ifdef HAVE_REGEXEC
	int i;
	regex_t re;
#endif

	if ((p = strpbrk(buf, "\r\n")))
	    *p = '\0';

	p = buf;
	while (*p == ' ' || *p == '\t')	/* eat leading blanks */
	    p++;
	if (!*p)
	    continue;		/* skip empty lines */
	if (*p == '#')
	    continue;		/* skip comments */

	pattern = strtok(p, delim);
	server = strtok(NULL, delim);
	if (!pattern || !server)
	    err_quit(_("Cannot parse this line: %s"), p);
	p = strtok(NULL, delim);
	if (p)
	    err_quit(_("Cannot parse this line: %s"), p);

#ifdef HAVE_REGEXEC
	i = regcomp(&re, pattern, REG_EXTENDED | REG_ICASE | REG_NOSUB);
	if (i != 0) {
	    char m[1024];
	    regerror(i, &re, m, sizeof(m));
	    err_quit("Invalid regular expression '%s': %s", pattern, m);
	}

	i = regexec(&re, s, 0, NULL, 0);
	if (i == 0) {
	    regfree(&re);
	    fclose(fp);
	    return strdup(server);
	}
	if (i != REG_NOMATCH) {
	    char m[1024];
	    regerror(i, &re, m, sizeof(m));
	    err_quit("regexec: %s",  m);
	}
	regfree(&re);
#else
	if (domcmp(s, pattern)) {
	    fclose(fp);
	    return strdup(server);
	}
#endif
    }
    fclose(fp);
    return NULL;
}
#endif

/* Parses an user-supplied string and tries to guess the right whois server.
 * Returns a dinamically allocated buffer.
 */
char *guess_server(const char *s)
{
    unsigned long ip, as32;
    unsigned int i;
    const char *colon;

    /* IPv6 address */
    if ((colon = strchr(s, ':'))) {
	unsigned long v6prefix, v6net;

	/* RPSL hierarchical objects */
	if (strncaseeq(s, "as", 2)) {
	    if (isasciidigit(s[2]))
		return strdup(whereas(atol(s + 2)));
	    else
		return strdup("");
	}

	v6prefix = strtol(s, NULL, 16);

	if (v6prefix == 0)
	    return strdup("\x05");		/* unknown */

	v6net = (v6prefix << 16) + strtol(colon + 1, NULL, 16);/* second u16 */

	for (i = 0; ip6_assign[i].serv; i++) {
	    if ((v6net & (~0UL << (32 - ip6_assign[i].masklen)))
		    == ip6_assign[i].net)
		return strdup(ip6_assign[i].serv);
	}

	return strdup("\x06");			/* unknown allocation */
    }

    /* email address */
    if (strchr(s, '@'))
	return strdup("\x05");

    /* no dot and no hyphen means it's a NSI NIC handle or ASN (?) */
    if (!strpbrk(s, ".-")) {
	if (strncaseeq(s, "as", 2) &&		/* it's an AS */
		(isasciidigit(s[2]) || s[2] == ' '))
	    return strdup(whereas(atol(s + 2)));
	if (*s == '!')	/* NSI NIC handle */
	    return strdup("whois.networksolutions.com");
	else
	    return strdup("\x05"); /* probably a unknown kind of nic handle */
    }

    /* ASN32? */
    if (strncaseeq(s, "as", 2) && s[2] && (as32 = asn32_to_long(s + 2)) != 0)
	return strdup(whereas32(as32));

    /* smells like an IP? */
#ifdef HAVE_INET_PTON
    if (inet_pton(AF_INET, s, &ip) > 0) {
	ip = ntohl(ip);
#else
    if ((ip = myinet_aton(s))) {
#endif
	for (i = 0; ip_assign[i].serv; i++)
	    if ((ip & ip_assign[i].mask) == ip_assign[i].net)
		return strdup(ip_assign[i].serv);
	return strdup("\x05");		/* not in the unicast IPv4 space */
    }

    /* check the TLDs list */
    for (i = 0; tld_serv[i]; i += 2)
	if (domcmp(s, tld_serv[i]))
	    return strdup(tld_serv[i + 1]);

    /* use the default server name for "new" gTLDs */
    if (is_new_gtld(s)) {
	char *server;
	const char *p, *tld = NULL;

	for (p = s; *p; p++)		/* look for the TLD */
	    if (*p == '.')
		tld = p;

	server = malloc(strlen("whois.nic") + strlen(tld) + 1);
	strcpy(server, "whois.nic");
	strcat(server, tld);
	return(server);
    }

    /* no dot but hyphen */
    if (!strchr(s, '.')) {
	/* search for strings at the start of the word */
	for (i = 0; nic_handles[i]; i += 2)
	    if (strncaseeq(s, nic_handles[i], strlen(nic_handles[i])))
		return strdup(nic_handles[i + 1]);
	/* it's probably a network name */
	return strdup("");
    }

    /* has dot and maybe a hyphen and it's not in tld_serv[], WTF is it? */
    /* either a TLD or a NIC handle we don't know about yet */
    return strdup("\x05");
}

const char *whereas32(const unsigned long asn)
{
    int i;

    for (i = 0; as32_assign[i].serv; i++)
	if (asn >= as32_assign[i].first && asn <= as32_assign[i].last)
	    return as32_assign[i].serv;
    return "\x06";
}

const char *whereas(const unsigned long asn)
{
    int i;

    if (asn > 65535)
	return whereas32(asn);

    for (i = 0; as_assign[i].serv; i++)
	if (asn >= as_assign[i].first && asn <= as_assign[i].last)
	    return as_assign[i].serv;
    return "\x06";
}

/*
 * Construct the query string.
 * Determines the server character set as a side effect.
 * Returns a malloc'ed string which needs to be freed by the caller.
 */
char *queryformat(const char *server, const char *flags, const char *query)
{
    char *buf;
    int i, isripe = 0;

    /* 64 bytes reserved for server-specific flags added later */
    buf = malloc(strlen(flags) + strlen(query) + strlen(client_tag) + 64);
    *buf = '\0';

    for (i = 0; ripe_servers[i]; i++)
	if (streq(server, ripe_servers[i])) {
	    sprintf(buf + strlen(buf), "-V %s ", client_tag);
	    isripe = 1;
	    break;
	}

    if (*flags) {
	if (!isripe)
	    puts(_("Warning: RIPE flags used with a traditional server."));
	strcat(buf, flags);
    }

#ifdef HAVE_ICONV
    simple_recode_iconv_close();
    for (i = 0; servers_charset[i].name; i++)
	if (streq(server, servers_charset[i].name)) {
	    simple_recode_input_charset = servers_charset[i].charset;
	    if (servers_charset[i].options) {
		strcat(buf, servers_charset[i].options);
		strcat(buf, " ");
	    }
	    break;
	}

    /* Use UTF-8 by default for "new" gTLDs */
    if (!simple_recode_input_charset &&		/* was not in the database */
	    !strchr(query, ' ') &&		/* and has no parameters */
	    is_new_gtld(query))			/* and is a "new" gTLD: */
	simple_recode_input_charset = "utf-8";	/* then try UTF-8 */
#endif

#ifdef HAVE_LIBIDN
# define DENIC_PARAM_ACE ",ace"
#else
# define DENIC_PARAM_ACE ""
#endif
#ifdef HAVE_ICONV
# define DENIC_PARAM_CHARSET ""
#else
# define DENIC_PARAM_CHARSET " -C US-ASCII"
#endif

    /* add useful default flags if there are no flags or multiple arguments */
    if (isripe) { }
    else if (strchr(query, ' ') || *flags) { }
    else if (streq(server, "whois.denic.de") && domcmp(query, ".de"))
	strcat(buf, "-T dn" DENIC_PARAM_ACE DENIC_PARAM_CHARSET " ");
    else if (streq(server, "whois.dk-hostmaster.dk") && domcmp(query, ".dk"))
	strcat(buf, "--show-handles ");

    /* mangle and add the query string */
    if (!isripe && streq(server, "whois.nic.ad.jp") &&
	    strncaseeq(query, "AS", 2) && isasciidigit(query[2])) {
	strcat(buf, "AS ");
	strcat(buf, query + 2);
    }
    else if (!isripe && streq(server, "whois.arin.net") &&
	    !strrchr(query, ' ')) {
	if (strncaseeq(query, "AS", 2) && isasciidigit(query[2])) {
	    strcat(buf, "a ");
	    strcat(buf, query + 2);
	} else if (myinet_aton(query) || strchr(query, ':')) {
	    strcat(buf, "n + ");
	    strcat(buf, query);
	} else
	    strcat(buf, query);
    }
    else
	strcat(buf, query);

    /* ask for english text */
    if (!isripe && (streq(server, "whois.nic.ad.jp") ||
	    streq(server, "whois.jprs.jp")) && japanese_locale())
	strcat(buf, "/e");

    return buf;
}

/* the first parameter contains the state of this simple state machine:
 * HIDE_DISABLED: hidden text finished
 * HIDE_NOT_STARTED: hidden text not seen yet
 * >= 0: currently hiding message hide_strings[*hiding]
 */
int hide_line(int *hiding, const char *const line)
{
    int i;

    if (*hiding == HIDE_TO_THE_END) {
	return 1;
    } else if (*hiding == HIDE_DISABLED) {
	return 0;
    } else if (*hiding == HIDE_NOT_STARTED) {	/* looking for smtng to hide */
	for (i = 0; hide_strings[i] != NULL; i += 2) {
	    if (strneq(line, hide_strings[i], strlen(hide_strings[i]))) {
		if (hide_strings[i + 1] == NULL)
		    *hiding = HIDE_TO_THE_END;	/* all the remaining output */
		else
		    *hiding = i;		/* start hiding */
		return 1;			/* and hide this line */
	    }
	}
	return 0;				/* don't hide this line */
    } else if (*hiding > HIDE_NOT_STARTED) {	/* hiding something */
	if (*hide_strings[*hiding + 1] == '\0')	{ /*look for a blank line?*/
	    if (*line == '\n' || *line == '\r' || *line == '\0') {
		*hiding = HIDE_DISABLED;	/* stop hiding */
		return 0;		/* but do not hide the blank line */
	    }
	} else {				/*look for a matching string*/
	    if (strneq(line, hide_strings[*hiding + 1],
			strlen(hide_strings[*hiding + 1]))) {
		*hiding = HIDE_DISABLED;	/* stop hiding */
		return 1;			/* but hide the last line */
	    }
	}
	return 1;				/* we are hiding, so do it */
    } else
	return 0;
}

/* returns a string which should be freed by the caller, or NULL */
char *do_query(const int sock, const char *query)
{
    char *temp, *p, buf[2000];
    FILE *fi;
    int hide = hide_discl;
    char *referral_server = NULL;

    temp = malloc(strlen(query) + 2 + 1);
    strcpy(temp, query);
    strcat(temp, "\r\n");

    fi = fdopen(sock, "r");
    if (write(sock, temp, strlen(temp)) < 0)
	err_sys("write");
    free(temp);

    while (fgets(buf, sizeof(buf), fi)) {
	/* 6bone-style referral:
	 * % referto: whois -h whois.arin.net -p 43 as 1
	 */
	if (!referral_server && strneq(buf, "% referto:", 10)) {
	    char nh[256], np[16], nq[1024];

	    if (sscanf(buf, REFERTO_FORMAT, nh, np, nq) == 3) {
		/* XXX we are ignoring the new query string */
		referral_server = malloc(strlen(nh) + 1 + strlen(np) + 1);
		sprintf(referral_server, "%s:%s", nh, np);
	    }
	}

	/* ARIN referrals:
	 * ReferralServer: rwhois://rwhois.fuse.net:4321/
	 * ReferralServer: whois://whois.ripe.net
	 */
	if (!referral_server && strneq(buf, "ReferralServer:", 15)) {
	    if ((p = strstr(buf, "rwhois://")))
		referral_server = strdup(p + 9);
	    else if ((p = strstr(buf, "whois://")))
		referral_server = strdup(p + 8);
	    if (referral_server && (p = strpbrk(referral_server, "/\r\n")))
		*p = '\0';
	}

	if (hide_line(&hide, buf))
	    continue;

	if ((p = strpbrk(buf, "\r\n")))
	    *p = '\0';
	recode_fputs(buf, stdout);
	fputc('\n', stdout);
    }

    if (ferror(fi))
	err_sys("fgets");
    fclose(fi);

    if (hide > HIDE_NOT_STARTED && hide != HIDE_TO_THE_END)
	err_quit(_("Catastrophic error: disclaimer text has been changed.\n"
		   "Please upgrade this program.\n"));

    return referral_server;
}

char *query_crsnic(const int sock, const char *query)
{
    char *temp, *p, buf[2000];
    FILE *fi;
    int hide = hide_discl;
    char *referral_server = NULL;
    int state = 0;

    temp = malloc(strlen(query) + 1 + 2 + 1);
    *temp = '=';
    strcpy(temp + 1, query);
    strcat(temp, "\r\n");

    fi = fdopen(sock, "r");
    if (write(sock, temp, strlen(temp)) < 0)
	err_sys("write");
    free(temp);

    while (fgets(buf, sizeof(buf), fi)) {
	/* If there are multiple matches only the server of the first record
	   is queried */
	if (state == 0 && strneq(buf, "   Domain Name:", 15))
	    state = 1;
	if (state == 1 && strneq(buf, "   Whois Server:", 16)) {
	    for (p = buf; *p != ':'; p++);	/* skip until colon */
	    for (p++; *p == ' '; p++);		/* skip colon and spaces */
	    referral_server = strdup(p);
	    if ((p = strpbrk(referral_server, "\r\n ")))
		*p = '\0';
	    state = 2;
	}

	/* the output must not be hidden or no data will be shown for
	   host records and not-existing domains */
	if (hide_line(&hide, buf))
	    continue;

	if ((p = strpbrk(buf, "\r\n")))
	    *p = '\0';
	recode_fputs(buf, stdout);
	fputc('\n', stdout);
    }

    if (ferror(fi))
	err_sys("fgets");
    fclose(fi);

    return referral_server;
}

char *query_afilias(const int sock, const char *query)
{
    char *temp, *p, buf[2000];
    FILE *fi;
    int hide = hide_discl;
    char *referral_server = NULL;
    int state = 0;

    temp = malloc(strlen(query) + 2 + 1);
    strcpy(temp, query);
    strcat(temp, "\r\n");

    fi = fdopen(sock, "r");
    if (write(sock, temp, strlen(temp)) < 0)
	err_sys("write");
    free(temp);

    while (fgets(buf, sizeof(buf), fi)) {
	if (state == 0 && strneq(buf, "Domain Name:", 12))
	    state = 1;
	if (state == 1 && strneq(buf, "Whois Server:", 13)) {
	    for (p = buf; *p != ':'; p++);	/* skip until colon */
	    for (p++; *p == ' '; p++);		/* skip colon and spaces */
	    referral_server = strdup(p);
	    if ((p = strpbrk(referral_server, "\r\n ")))
		*p = '\0';
	}

	if (hide_line(&hide, buf))
	    continue;

	if ((p = strpbrk(buf, "\r\n")))
	    *p = '\0';
	recode_fputs(buf, stdout);
	fputc('\n', stdout);
    }

    if (ferror(fi))
	err_sys("fgets");
    fclose(fi);

    if (hide > HIDE_NOT_STARTED && hide != HIDE_TO_THE_END)
	err_quit(_("Catastrophic error: disclaimer text has been changed.\n"
		   "Please upgrade this program.\n"));

    return referral_server;
}

int openconn(const char *server, const char *port)
{
    int fd = -1;
    int timeout = 10;
#ifdef HAVE_GETADDRINFO
    int err;
    struct addrinfo hints, *res, *ai;
#else
    struct hostent *hostinfo;
    struct servent *servinfo;
    struct sockaddr_in saddr;
#endif

    alarm(60);

#ifdef HAVE_GETADDRINFO
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
#ifdef HAVE_LIBIDN
    hints.ai_flags |= AI_IDN;
#endif

    if ((err = getaddrinfo(server, port ? port : "nicname", &hints, &res))
	    != 0) {
	if (err == EAI_SYSTEM)
	    err_sys("getaddrinfo(%s)", server);
	else
	    err_quit("getaddrinfo(%s): %s", server, gai_strerror(err));
    }

    for (ai = res; ai; ai = ai->ai_next) {
	/* no timeout for the last address. is this a good idea? */
	if (!ai->ai_next)
	    timeout = 0;
	if ((fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0)
	    continue;		/* ignore */
	if (connect_with_timeout(fd, (struct sockaddr *)ai->ai_addr,
		    ai->ai_addrlen, timeout) == 0)
	    break;		/* success */
	close(fd);
    }
    freeaddrinfo(res);

    if (!ai)
	err_sys("connect");
#else
    if ((hostinfo = gethostbyname(server)) == NULL)
	err_quit(_("Host %s not found."), server);
    if ((fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP)) < 0)
	err_sys("socket");
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_addr = *(struct in_addr *) hostinfo->h_addr;
    saddr.sin_family = AF_INET;
    if (!port) {
	saddr.sin_port = htons(43);
    } else if ((saddr.sin_port = htons(atoi(port))) == 0) {
	if ((servinfo = getservbyname(port, "tcp")) == NULL)
	    err_quit(_("%s/tcp: unknown service"), port);
	saddr.sin_port = servinfo->s_port;
    }
    if (connect_with_timeout(fd, (struct sockaddr *)&saddr, sizeof(saddr),
		timeout) < 0)
	err_sys("connect");
#endif

    return fd;
}

int connect_with_timeout(int fd, const struct sockaddr *addr,
	socklen_t addrlen, int timeout)
{
    int savedflags, rc, connect_errno, opt;
    unsigned int len;
    fd_set fd_w;
    struct timeval tv;

    if (timeout <= 0)
	return (connect(fd, addr, addrlen));

    if ((savedflags = fcntl(fd, F_GETFL, 0)) < 0)
	return -1;

    /* set the socket non-blocking, so connect(2) will return immediately */
    if (fcntl(fd, F_SETFL, savedflags | O_NONBLOCK) < 0)
	return -1;

    rc = connect(fd, addr, addrlen);

    /* set the socket to block again */
    connect_errno = errno;
    if (fcntl(fd, F_SETFL, savedflags) < 0)
	return -1;
    errno = connect_errno;

    if (rc == 0 || errno != EINPROGRESS)
	return rc;

    FD_ZERO(&fd_w);
    FD_SET(fd, &fd_w);
    tv.tv_sec = timeout;
    tv.tv_usec = 0;

    /* loop until an error or the timeout has expired */
    do {
	rc = select(fd + 1, NULL, &fd_w, NULL, &tv);
    } while (rc == -1 && errno == EINTR);

    if (rc == 0) {		/* timed out */
	errno = ETIMEDOUT;
	return -1;
    }

    if (rc < 0 || rc > 1)	/* select failed */
	return rc;

    /* rc == 1: success. check for errors */
    len = sizeof(opt);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &opt, &len) < 0)
	return -1;

    /* and report them */
    if (opt != 0) {
	errno = opt;
	return -1;
    }

    return 0;
}

void alarm_handler(int signum)
{
    close(sockfd);
    err_quit(_("Timeout."));
}

void sighandler(int signum)
{
    close(sockfd);
    err_quit(_("Interrupted by signal %d..."), signum);
}

int japanese_locale(void) {
    char *lang;

    lang = getenv("LC_MESSAGE");
    if (lang) {
	if (strneq(lang, "ja", 2))
	    return 0;
	return 1;
    }

    lang = getenv("LANG");
    if (lang && strneq(lang, "ja", 2))
	return 0;
    return 1;
}

/* check if dom ends with tld */
int domcmp(const char *dom, const char *tld)
{
    const char *p, *q;

    for (p = dom; *p; p++); p--;	/* move to the last char */
    for (q = tld; *q; q++); q--;
    while (p >= dom && q >= tld && tolower(*p) == *q) {	/* compare backwards */
	if (q == tld)			/* start of the second word? */
	    return 1;
	p--; q--;
    }
    return 0;
}

int is_new_gtld(const char *s)
{
    int i;

    for (i = 0; new_gtlds[i]; i++)
	if (domcmp(s, new_gtlds[i]))
	    return 1;

    return 0;
}

/*
 * Attempt to normalize a query by removing trailing dots and whitespace,
 * then convert the domain to punycode.
 * The function assumes that the domain is the last token of they query.
 * Returns a malloc'ed string which needs to be freed by the caller.
 */
char *normalize_domain(const char *dom)
{
    char *p, *ret;
#ifdef HAVE_LIBIDN
    char *domain_start = NULL;
#endif

    ret = strdup(dom);
    /* eat trailing dots and blanks */
    p = ret + strlen(ret);
    for (; *p == '.' || *p == ' ' || *p == '\t' || p == ret; p--)
	*p = '\0';

#ifdef HAVE_LIBIDN
    /* find the start of the last word if there are spaces in the query */
    for (p = ret; *p; p++)
	if (*p == ' ')
	    domain_start = p + 1;

    if (domain_start) {
	char *q, *r;
	int prefix_len;

	if (idna_to_ascii_lz(domain_start, &q, 0) != IDNA_SUCCESS)
	    return ret;

	/* reassemble the original query in a new buffer */
	prefix_len = domain_start - ret;
	r = malloc(prefix_len + strlen(q) + 1);
	strncpy(r, ret, prefix_len);
	r[prefix_len] = '\0';
	strcat(r, q);

	free(q);
	free(ret);
	return r;
    } else {
	char *q;

	if (idna_to_ascii_lz(ret, &q, 0) != IDNA_SUCCESS)
	    return ret;

	free(ret);
	return q;
    }
#else
    return ret;
#endif
}

/* server and port have to be freed by the caller */
void split_server_port(const char *const input,
	char **server, char **port) {
    char *p;

    if (*input == '[' && (p = strchr(input, ']'))) {	/* IPv6 */
	char *s;
	int len = p - input - 1;

	*server = s = malloc(len + 1);
	memcpy(s, input + 1, len);
	*(s + len) = '\0';

	p = strchr(p, ':');
	if (p && *(p + 1) != '\0')
	    *port = strdup(p + 1);			/* IPv6 + port */
    } else if ((p = strchr(input, ':')) &&		/* IPv6, no port */
	    strchr(p + 1, ':')) {			/*   and no brackets */
	*server = strdup(input);
    } else if ((p = strchr(input, ':'))) {		/* IPv4 + port */
	char *s;
	int len = p - input;

	*server = s = malloc(len + 1);
	memcpy(s, input, len);
	*(s + len) = '\0';

	p++;
	if (*p != '\0')
	    *port = strdup(p);
    } else {						/* IPv4, no port */
	*server = strdup(input);
    }

    /* change the server name to lower case */
    for (p = (char *) *server; *p && *p != '\0'; p++)
	*p = tolower(*p);
}

char *convert_6to4(const char *s)
{
    char *new;

#ifdef HAVE_INET_PTON
    struct in6_addr ipaddr;
    unsigned char *ip;

    if (inet_pton(AF_INET6, s, &ipaddr) <= 0)
	return strdup("0.0.0.0");

    ip = (unsigned char *)&ipaddr;
    new = malloc(sizeof("255.255.255.255"));
    sprintf(new, "%d.%d.%d.%d", *(ip + 2), *(ip + 3), *(ip + 4), *(ip + 5));
#else
    int items;
    unsigned int a, b;
    char c;

    items = sscanf(s, "2002:%x:%x%c", &a, &b, &c);

    if (items <= 0 || items == 2 || (items == 3 && c != ':'))
	return strdup("0.0.0.0");

    if (items == 1) {
	items = sscanf(s, "2002:%x:%c", &a, &c);
	if (items != 2 || c != ':')
	    return strdup("0.0.0.0");
	b = 0;
    }

    new = malloc(sizeof("255.255.255.255"));
    sprintf(new, "%d.%d.%d.%d", a >> 8, a & 0xff, b >> 8, b & 0xff);
#endif

    return new;
}

char *convert_teredo(const char *s)
{
    char *new;

#ifdef HAVE_INET_PTON
    struct in6_addr ipaddr;
    unsigned char *ip;

    if (inet_pton(AF_INET6, s, &ipaddr) <= 0)
	return strdup("0.0.0.0");

    ip = (unsigned char *)&ipaddr;
    new = malloc(sizeof("255.255.255.255"));
    sprintf(new, "%d.%d.%d.%d", *(ip + 12) ^ 0xff, *(ip + 13) ^ 0xff,
	    *(ip + 14) ^ 0xff, *(ip + 15) ^ 0xff);
#else
    unsigned int a, b;

    if (sscanf(s, "2001:%*[^:]:%*[^:]:%*[^:]:%*[^:]:%*[^:]:%x:%x", &a, &b) != 2)
	return strdup("0.0.0.0");

    a ^= 0xffff;
    b ^= 0xffff;
    new = malloc(sizeof("255.255.255.255"));
    sprintf(new, "%d.%d.%d.%d", a >> 8, a & 0xff, b >> 8, b & 0xff);
#endif

    return new;
}

char *convert_inaddr(const char *s)
{
    char *new;
    char *endptr;
    long int a, b = 0, c = 0;

    errno = 0;

    a = strtol(s, &endptr, 10);
    if (errno || a < 0 || a > 255 || *endptr != '.')
	return strdup("0.0.0.0");

    if (domcmp(endptr + 1, ".in-addr.arpa")) {
	b = strtol(endptr + 1, &endptr, 10);			/* 1.2. */
	if (errno || b < 0 || b > 255 || *endptr != '.')
	    return strdup("0.0.0.0");

	if (domcmp(endptr + 1, ".in-addr.arpa")) {
	    c = strtol(endptr + 1, &endptr, 10);		/* 1.2.3. */
	    if (errno || c < 0 || c > 255 || *endptr != '.')
		return strdup("0.0.0.0");

	    if (domcmp(endptr + 1, ".in-addr.arpa"))
		return strdup("0.0.0.0");
	}
    }

    new = malloc(sizeof("255.255.255.255"));
    sprintf(new, "%ld.%ld.%ld.0", c, b, a);
    return new;
}

#ifndef HAVE_INET_PTON
unsigned long myinet_aton(const char *s)
{
    unsigned long a, b, c, d;
    int elements;
    char junk;

    if (!s)
	return 0;
    elements = sscanf(s, "%lu.%lu.%lu.%lu%c", &a, &b, &c, &d, &junk);
    if (!(elements == 4 || (elements == 5 && junk == '/')))
	return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255)
	return 0;
    return (a << 24) + (b << 16) + (c << 8) + d;
}
#endif

unsigned long asn32_to_long(const char *s)
{
    unsigned long a, b;
    char junk;

    if (!s)
	return 0;
    if (sscanf(s, "%lu.%lu%c", &a, &b, &junk) != 2)
	return 0;
    if (a > 65535 || b > 65535)
	return 0;
    return (a << 16) + b;
}

int isasciidigit(const char c) {
    return (c >= '0' && c <= '9') ? 1 : 0;
}

/* http://www.ripe.net/ripe/docs/databaseref-manual.html */

void usage(int error)
{
    fprintf((EXIT_SUCCESS == error) ? stdout : stderr, _(
"Usage: whois [OPTION]... OBJECT...\n\n"
"-h HOST, --host HOST   connect to server HOST\n"
"-p PORT, --port PORT   connect to PORT\n"
"-H                     hide legal disclaimers\n"
"      --verbose        explain what is being done\n"
"      --help           display this help and exit\n"
"      --version        output version information and exit\n"
"\n"
"These flags are supported by whois.ripe.net and some RIPE-like servers:\n"
"-l                     find the one level less specific match\n"
"-L                     find all levels less specific matches\n"
"-m                     find all one level more specific matches\n"
"-M                     find all levels of more specific matches\n"
"-c                     find the smallest match containing a mnt-irt attribute\n"
"-x                     exact match\n"
"-b                     return brief IP address ranges with abuse contact\n"
"-B                     turn off object filtering (show email addresses)\n"
"-G                     turn off grouping of associated objects\n"
"-d                     return DNS reverse delegation objects too\n"
"-i ATTR[,ATTR]...      do an inverse look-up for specified ATTRibutes\n"
"-T TYPE[,TYPE]...      only look for objects of TYPE\n"
"-K                     only primary keys are returned\n"
"-r                     turn off recursive look-ups for contact information\n"
"-R                     force to show local copy of the domain object even\n"
"                       if it contains referral\n"
"-a                     also search all the mirrored databases\n"
"-s SOURCE[,SOURCE]...  search the database mirrored from SOURCE\n"
"-g SOURCE:FIRST-LAST   find updates from SOURCE from serial FIRST to LAST\n"
"-t TYPE                request template for object of TYPE\n"
"-v TYPE                request verbose template for object of TYPE\n"
"-q [version|sources|types]  query specified server info\n"
));
    exit(error);
}

