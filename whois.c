/* Copyright 1999 by Marco d'Itri <md@linux.it>.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* System library */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>

/* Application-specific */
#include "config.h"
#include "data.h"
#include "whois.h"

/* Global variables */
int sockfd, verb = 0;

int main(int argc, char *argv[])
{
    int ch, nopar = 0, optC = 0;
    const char *server = NULL;
    char *p, *q, qstring[256] = "\0", fstring[64] = "\0", *port = NULL,
     defaultserv[] = "whois.internic.net";

#ifdef ENABLE_NLS
    setlocale(LC_MESSAGES, "");
    bindtextdomain(NLS_CAT_NAME, LOCALEDIR);
    textdomain(NLS_CAT_NAME);
#endif

    while ((ch = getopt(argc, argv, "acCFg:h:i:LmMp:rRs:St:T:v:V")) > 0) {
	/* RIPE flags */
	if (strchr(ripeflags, ch)) {
	    for (p = fstring; *p != '\0'; p++);
	    sprintf(p--, "-%c ", ch);
	    continue;
	}
	if (strchr(ripeflagsp, ch)) {
	    for (p = fstring; *p != '\0'; p++);
	    sprintf(p--, "-%c %s ", ch, optarg);
	    if (ch == 't' || ch == 'v')
		nopar = 1;
	    continue;
	}
	/* program flags */
	switch (ch) {
	case 'h':
	    server = q = malloc(strlen(optarg) + 1);
	    for (p = optarg; *p != '\0'; *q++ = tolower(*p++));
	    break;
	case 'p':
	    port = optarg;
	    break;
	case 'C':
	    optC = 1;
	    break;
	case 'V':
	    verb = 1;
	    break;
	default:
	    usage();
	}
    }
    argc -= optind;
    argv += optind;

    if (argc == 0 && !nopar)	/* there is no parameter */
	usage();

    /* parse other parameters */
    if (!nopar) {
	strcpy(qstring, *argv++);
	argc--;
	while (argc-- > 0) {
	    strcat(qstring, " ");
	    strcat(qstring, *argv);
	}
    }

    if (optC && domfind(qstring, gtlds)) {
	if (verb)
	    fputs(_("Connecting to whois.crsnic.net.\n"), stdout);
	sockfd = openconn("whois.crsnic.net", "43");
	server = query_crsnic(sockfd, qstring);
	if (verb && server)
	    printf(_("\nDetected CRSNIC referral to %s.\n\n"), server);
	closeconn(sockfd);
    }

    if (!server) {
	if (!(server = whichwhois(qstring))) {
	    server = defaultserv;
	    if (verb)
		printf(_("Using default server %s.\n"), server);
	} else if (verb)
	    printf(_("Using server %s.\n"), server);
    }

    p = queryformat(server, fstring, qstring);
    if (verb) {
	printf(_("Query string: \"%s\"\n\n"), p);
    }
    strcat(p, "\r\n");

    signal(SIGTERM, sighandler);
    signal(SIGINT, sighandler);

    sockfd = openconn(server, port);
    do_query(sockfd, p);
    closeconn(sockfd);

    exit(0);
}

const char *whichwhois(const char *s)
{
    unsigned long ip;
    unsigned int i;

    /* -v or -t has been used */
    if (*s == '\0')
	return "whois.ripe.net";

    /* no dot and no hyphen means it's a internic NIC handle or an AS (?) */
    if (!strpbrk(s, ".-")) {
	if (strncasecmp(s, "AS", 2) == 0) {	/* it's an AS */
	    return whereas(atoi(s + 2), as_assign);
	} else			/* it's an internic NIC handle (?) */
	    return "whois.internic.net";
    }

    /* IPv6 address */
    if (strchr(s, ':'))
	return "whois.6bone.net";

    /* smells like an IP? */
    if ((ip = myinet_aton(s))) {
	for (i = 0; ip_assign[i].serv; i++)
	    if ((ip & ip_assign[i].mask) == ip_assign[i].net)
		return ip_assign[i].serv;
	if (verb)
	    fputs(_("I don't know where this IP has been delegated.\n"
		    "I'll try ARIN and hope for the best...\n"), stdout);
	return "whois.arin.net";
    }

    /* check TLD list */
    for (i = 0; tld_serv[i]; i += 2)
	if (domcmp(s, tld_serv[i]))
	    return tld_serv[i + 1];

    /* no dot but hyphen, check for ARIN netblock names */
    if (!strchr(s, '.')) {
	for (i = 0; arin_nets[i]; i++)
	    if (!strncasecmp(s, arin_nets[i], strlen(arin_nets[i])))
		return "whois.arin.net";
	/* could be one of *NETBLK-RIPE* *NET-RIPE* *APNIC* *AUNIC-AU* */
	if (verb)
	    fputs(_("I guess it's a netblock name but I don't know where to"
		    " look it up.\n"), stdout);
	return "whois.arin.net";
    }

    /* has dot and hypen and it's not in tld_serv[], WTF is it? */
    if (verb)
	fputs(_("I guess it's a domain but I don't know where to look it"
		" up.\n"), stdout);

    return NULL;
}

const char *whereas(unsigned short asn, struct as_del aslist[])
{
    int i;

    if (asn > 14335)
	puts(_("Unknown AS number. Please upgrade this program."));
    for (i = 0; aslist[i].serv; i++)
	if (asn >= aslist[i].first && asn <= aslist[i].last)
	    return aslist[i].serv;
    return "whois.arin.net";
}

char *queryformat(const char *server, const char *flags, const char *query)
{
    char *buf;
    int i, isripe = 0;

    buf = malloc(QUERYBUFSIZE + 1);	/* +1 is for ARIN AS queries */
    //*buf = '\0';
    for (i = 0; ripe_servers[i]; i++)
	if (strcmp(server, ripe_servers[i]) == 0) {
	    strcat(buf, "-V" IDSTRING " ");
	    isripe = 1;
	    break;
	}
    if (*flags != '\0') {
	if (isripe && *flags != '\0')
	    puts(_("Warning: RIPE flags ignored for a traditional server."));
	else
	    strcat(buf, flags);
    }
    if (!isripe && strcmp(server, "whois.arin.net") == 0 &&
	    strncasecmp(query, "AS", 2) == 0 &&
	    query[2] >= '0' && query[2] <= '9') {
	sprintf(buf, "AS ");
	strcat(buf, query + 2);
    } else
	strcat(buf, query);
    if (!isripe && strcmp(server, "whois.nic.ad.jp") == 0) {
	char *lang = getenv("LANG");	/* not a perfect check, but... */
	if (lang && (strncmp(getenv("LANG"), "ja", 2) != 0))
	    strcat(buf, "/e");	/* ask for english text */
    }
    return buf;
}

void do_query(const int sock, const char *query)
{
    char buf[100];
    FILE *fi;
#ifdef HIDE_DISCL
    int hide = 0;
#endif

    fi = fdopen(sock, "r");
    if (write(sock, query, strlen(query)) < 0)
	err_sys("write");
    while (fgets(buf, 100, fi)) {	/* XXX errors? */
#ifdef HIDE_DISCL
	if (hide == 1) {
	    if (strncmp(buf, DISCL_END, sizeof(DISCL_END) - 1) == 0)
		hide = 2;	/* stop hiding */
	    continue;
	}
	if (hide == 0 &&
		strncmp(buf, DISCL_BEGIN, sizeof(DISCL_BEGIN) - 1) == 0) {
	    hide = 1;		/* start hiding */
	    continue;
	}
#endif
#ifdef EXT_6BONE
	/* % referto: whois -h whois.arin.net -p 43 as 1 */
	if (strncmp(buf, "% referto:", 10) == 0) {
	    char nh[256], np[16], nq[1024];

	    if (sscanf(buf, REFERTO_FORMAT, nh, np, nq) == 3) {
		int fd;

		if (verb)
		    printf(_("Detected referral to %s on %s.\n"), nq, nh);
		strcat(nq, "\r\n");
		fd = openconn(nh, np);
		do_query(sockfd, nq);
		closeconn(fd);
		continue;
	    }
	}
#endif
	fputs(buf, stdout);
    }
#ifdef HIDE_DISCL
    if (hide == 1)
	err_quit(_("Catastrophic error: INTERNIC changed the disclaimer text.\n"
		   "Please upgrade this program.\n"));
#endif
}

const char *query_crsnic(const int sock, const char *query)
{
    char *temp, buf[100], *ret = NULL;
    FILE *fi;

    temp = malloc(strlen(query) + 5 + 2 + 1);
    memcpy(temp, "dump ", 5);
    strcpy(temp + 5, query);
    strcat(temp, "\r\n");

    fi = fdopen(sock, "r");
    if (write(sock, temp, strlen(temp)) < 0)
	err_sys("write");
    while (fgets(buf, 100, fi)) {
	if (strncmp(buf, "   (2)", 6) == 0) {
	    char *p, *q;

	    for (p = buf; *p != ':'; p++);	/* skip until colon */
	    for (p++; *p == ' '; p++);		/* skip colon and spaces */
	    q = ret = malloc(strlen(p));
	    for (; *p != '\n' && *p != '\r'; *q++ = *p++); /* copy data */
	    *q = '\0';
	}
	fputs(buf, stdout);
    }

    free(temp);
    return ret;
}

int openconn(const char *server, const char *port)
{
    int s;
#ifdef HAVE_GETADDRINFO
    struct addrinfo hints, *res, *ressave;
#else
    struct hostent *hostinfo;
    struct servent *servinfo;
    struct sockaddr_in saddr;
#endif

#ifdef HAVE_GETADDRINFO
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((s = getaddrinfo(server, port ? port : "whois", &hints, &res)) != 0)
	err_quit("getaddrinfo: %s", gai_strerror(s));
    ressave = res;

    do {
	if ((s = socket(res->ai_family, res->ai_socktype, res->ai_protocol))<0)
	    continue;		/* ignore */
	if (connect(s, res->ai_addr, res->ai_addrlen) == 0)
	    break;		/* success */
	close(s);
    } while ((res = res->ai_next));	/* Thank you, W. Richard Stevens. */

    if (!res)
	err_sys("connect");
    freeaddrinfo(ressave);
#else
    if ((hostinfo = gethostbyname(server)) == NULL)
	err_quit(_("Host %s not found."), server);
    saddr.sin_addr = *(struct in_addr *) hostinfo->h_addr;
    if ((s = socket(PF_INET, SOCK_STREAM, IPPROTO_IP)) < 0)
	err_sys("socket");
    saddr.sin_family = AF_INET;
    if (!port) {
	saddr.sin_port = htons(43);
    } else if ((saddr.sin_port = htons(atoi(port))) == 0) {
	if ((servinfo = getservbyname(port, "tcp")) == NULL)
	    err_quit(_("%s/tcp: unknown service"), port);
	saddr.sin_port = servinfo->s_port;
    }
    if (connect(s, &saddr, sizeof(saddr)) < 0)
	err_sys("connect");
#endif
    return (s);
}

void closeconn(const int fd)
{
    close(fd);
}

void sighandler(int signum)
{
    closeconn(sockfd);
    err_quit(_("Interrupted by signal %d..."), signum);
}

/* check if dom ends with tld */
int domcmp(const char *dom, const char *tld)
{
    const char *p, *q;

    if (!(p = strrchr(dom, *tld)))
	return 0;
    q = tld;
    while (tolower(*p) == *q)
	if (!(*p++ && *q++))
	    return 1;
    return 0;
}

/* check if dom ends with an element of tldlist[] */
int domfind(const char *dom, const char *tldlist[])
{
    int i;

    for (i = 0; tldlist[i]; i++)
	if (domcmp(dom, tldlist[i]))
	    return 1;
    return 0;
}

unsigned long myinet_aton(const char *s)
{
    int a, b, c, d;

    if (!s)
	return 0;
    if (sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
	return 0;
    return (a << 24) + (b << 16) + (c << 8) + d;
}

void usage(void)
{
    fputs(_(
"Usage: whois [OPTION]... OBJECT...\n\n"
"-a                     search all databases\n"
"-C                     first query CRSNIC to find GTLD registrar\n"
"-F                     fast raw output (implies -r)\n"
"-g SOURCE:FIRST-LAST   find updates from SOURCE from serial FIRST to LAST\n"
"-h HOST                connect to server HOST\n"
"-i ATTR[,ATTR]...      do an inverse lookup for specified ATTRibutes\n"
"-L                     find all Less specific matches\n"
"-M                     find all More specific matches\n"
"-m                     find first level more specific matches\n"
"-r                     turn off recursive lookups\n"
"-p PORT                connect to PORT\n"
"-R                     force to show local copy of the domain object even\n"
"                       if it contains referral\n"
"-S                     tell server to leave out syntactic sugar\n"
"-s SOURCE[,SOURCE]...  search the database from SOURCE\n"
"-T TYPE[,TYPE]...      only look for objects of TYPE\n"
"-t TYPE                requests template for object of TYPE ('all' for a list)\n"
"-v TYPE                requests verbose template for object of TYPE\n"
"-V                     explain what is being done\n\n"
"Version " VERSION ". Please report bugs to <md@linux.it>.\n"
	), stderr);
    exit(1);
}


/* Error routines */
void err_sys(const char *fmt,...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, ": %s\n", strerror(errno));
    va_end(ap);
    exit(2);
}

void err_quit(const char *fmt,...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputs("\n", stderr);
    va_end(ap);
    exit(2);
}

