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
#include "config.h"
#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#endif
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
#include "data.h"
#include "whois.h"

/* Global variables */
int sockfd, verb = 0;

#ifdef ALWAYS_HIDE_DISCL
int hide_discl = 0;
#else
int hide_discl = 2;
#endif

#ifdef HAVE_GETOPT_LONG
static struct option longopts[] = {
    {"help",	no_argument,		NULL, 0  },
    {"version",	no_argument,		NULL, 1  },
    {"verbose",	no_argument,		NULL, 'V'},
    {"server",	required_argument,	NULL, 'h'},
    {"host",	required_argument,	NULL, 'h'},
    {NULL,	0,			NULL, 0  }
};
#endif

int main(int argc, char *argv[])
{
    int ch, nopar = 0;
    const char *server = NULL, *port = NULL;
    char *p, *q, *qstring, fstring[64] = "\0";
    extern char *optarg;
    extern int optind;

#ifdef ENABLE_NLS
    setlocale(LC_MESSAGES, "");
    bindtextdomain(NLS_CAT_NAME, LOCALEDIR);
    textdomain(NLS_CAT_NAME);
#endif

    while ((ch = GETOPT_LONGISH(argc, argv, "acFg:h:Hi:lLmMp:q:rRs:St:T:v:Vx",
				longopts, 0)) > 0) {
	/* RIPE flags */
	if (strchr(ripeflags, ch)) {
	    for (p = fstring; *p != '\0'; p++);
	    sprintf(p--, "-%c ", ch);
	    continue;
	}
	if (strchr(ripeflagsp, ch)) {
	    for (p = fstring; *p != '\0'; p++);
	    sprintf(p--, "-%c %s ", ch, optarg);
	    if (ch == 't' || ch == 'v' || ch == 'q')
		nopar = 1;
	    continue;
	}
	/* program flags */
	switch (ch) {
	case 'h':
	    server = q = malloc(strlen(optarg) + 1);
	    for (p = optarg; *p != '\0' && *p != ':'; *q++ = tolower(*p++));
	    if (*p == ':')
		port = p + 1;
	    *q = '\0';
	    break;
	case 'H':
	    hide_discl = 0;	/* enable disclaimers hiding */
	    break;
	case 'p':
	    port = optarg;
	    break;
	case 'V':
	    verb = 1;
	    break;
	case 1:
#ifdef VERSION
	    fprintf(stderr, _("Version %s.\n\nReport bugs to %s.\n"),
		    VERSION, "<md+whois@linux.it>");
#else
	    fprintf(stderr, "%s %s\n", inetutils_package, inetutils_version);
#endif
	    exit(0);
	default:
	    usage();
	}
    }
    argc -= optind;
    argv += optind;

    if (argc == 0 && !nopar)	/* there is no parameter */
	usage();

    /* On some systems realloc only works on non-NULL buffers */
    qstring = malloc(1);
    *qstring = '\0';

    /* parse other parameters, if any */
    if (!nopar) {
	int qslen = 0;

	while (1) {
	    qslen += strlen(*argv) + 1 + 1;
	    qstring = realloc(qstring, qslen);
	    strcat(qstring, *argv++);
	    if (argc == 1)
		break;
	    strcat(qstring, " ");
	    argc--;
	}
    }

    if (!server && domfind(qstring, gtlds)) {
	if (verb)
	    puts(_("Connecting to whois.internic.net."));
	sockfd = openconn("whois.internic.net", NULL);
	server = query_crsnic(sockfd, qstring);
	closeconn(sockfd);
	if (!server)
	    exit(0);
	printf(_("\nFound InterNIC referral to %s.\n\n"), server);
    }

    if (!server) {
	server = whichwhois(qstring);
	switch (server[0]) {
	    case 0:
		if (!(server = getenv("WHOIS_SERVER")))
		    server = DEFAULTSERVER;
		if (verb)
		    printf(_("Using default server %s.\n"), server);
		break;
	    case 1:
		puts(_("This TLD has no whois server, but you can access the "
			    "whois database at"));
	    case 2:
		puts(server + 1);
		exit(0);
	    case 3:
		puts(_("This TLD has no whois server."));
		exit(0);
	    default:
		if (verb)
		    printf(_("Using server %s.\n"), server);
	}
    }

    if (getenv("WHOIS_HIDE"))
	hide_discl = 0;

    p = queryformat(server, fstring, qstring);
    if (verb)
	printf(_("Query string: \"%s\"\n\n"), p);
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

    /* IPv6 address */
    if (strchr(s, ':')) {
	if (strncasecmp(s, "2001:2", 6) == 0)	/* XXX ugly hack! */
	    return "whois.apnic.net";
	if (strncasecmp(s, "2001:4", 6) == 0)
	    return "whois.arin.net";
	if (strncasecmp(s, "2001:6", 6) == 0)
	    return "whois.ripe.net";
	/* if (strncasecmp(s, "3ffe", 4) == 0) */
	    return "whois.6bone.net";
    }

    /* email address */
    if (strchr(s, '@'))
	return "";

    /* no dot and no hyphen means it's a NSI NIC handle or ASN (?) */
    if (!strpbrk(s, ".-")) {
	const char *p;

	for (p = s; *p != '\0'; p++);		/* go to the end of s */
	if (strncasecmp(s, "as", 2) == 0 &&	/* it's an AS */
	    ((s[2] >= '0' && s[2] <= '9') || s[2] == ' '))
	    return whereas(atoi(s + 2), as_assign);
	else if (strncasecmp(p - 2, "jp", 2) == 0) /* JP NIC handle */
	    return "whois.nic.ad.jp";
	if (*p == '!')	/* NSI NIC handle */
	    return "whois.networksolutions.com";
	else /* it's a NSI NIC handle or something we don't know about */
	    return "";
    }

    /* smells like an IP? */
    if ((ip = myinet_aton(s))) {
	for (i = 0; ip_assign[i].serv; i++)
	    if ((ip & ip_assign[i].mask) == ip_assign[i].net)
		return ip_assign[i].serv;
	if (verb)
	    puts(_("I don't know where this IP has been delegated.\n"
		   "I'll try ARIN and hope for the best..."));
	return "whois.arin.net";
    }

    /* check TLD list */
    for (i = 0; tld_serv[i]; i += 2)
	if (domcmp(s, tld_serv[i]))
	    return tld_serv[i + 1];

    /* no dot but hyphen */
    if (!strchr(s, '.')) {
	/* search for strings at the start of the word */
	for (i = 0; nic_handles[i]; i += 2)
	    if (strncasecmp(s, nic_handles[i], strlen(nic_handles[i])) == 0)
		return nic_handles[i + 1];
	if (verb)
	    puts(_("I guess it's a netblock name but I don't know where to"
		   " look it up."));
	return "whois.arin.net";
    }

    /* has dot and hypen and it's not in tld_serv[], WTF is it? */
    if (verb)
	puts(_("I guess it's a domain but I don't know where to look it"
	       " up."));
    return "";
}

const char *whereas(int asn, struct as_del aslist[])
{
    int i;

    if (asn > 16383)
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

    /* +10 for CORE; +2 for \r\n; +1 for NULL */
    buf = malloc(strlen(flags) + strlen(query) + 10 + 2 + 1);
    *buf = '\0';
    for (i = 0; ripe_servers[i]; i++)
	if (strcmp(server, ripe_servers[i]) == 0) {
	    strcat(buf, "-V " IDSTRING " ");
	    isripe = 1;
	    break;
	}
    if (!isripe)
	for (i = 0; ripe_servers_old[i]; i++)
	    if (strcmp(server, ripe_servers_old[i]) == 0) {
		strcat(buf, "-V" IDSTRING " ");
		isripe = 1;
		break;
	    }
    if (*flags != '\0') {
	if (!isripe && strcmp(server, "whois.corenic.net") != 0)
	    puts(_("Warning: RIPE flags ignored for a traditional server."));
	else
	    strcat(buf, flags);
    }
    if (!isripe &&
	    (strcmp(server, "whois.arin.net") == 0 ||
	     strcmp(server, "whois.nic.mil") == 0) &&
	    strncasecmp(query, "AS", 2) == 0 &&
	    query[2] >= '0' && query[2] <= '9')
	sprintf(buf, "AS %s", query + 2);	/* fix query for ARIN */
    else if (!isripe && strcmp(server, "whois.corenic.net") == 0)
	sprintf(buf, "--machine %s", query);	/* machine readable output */
    else if (!isripe && strcmp(server, "whois.ncst.ernet.in") == 0 &&
	     !strchr(query, ' '))
	sprintf(buf, "domain %s", query);	/* ask for a domain */
    else if (!isripe && strcmp(server, "whois.nic.ad.jp") == 0) {
	char *lang = getenv("LANG");	/* not a perfect check, but... */
	if (!lang || (strncmp(lang, "ja", 2) != 0))
	    sprintf(buf, "%s/e", query);	/* ask for english text */
	else
	    strcat(buf, query);
    } else
	strcat(buf, query);
    return buf;
}

void do_query(const int sock, const char *query)
{
    char buf[200], *p;
    FILE *fi;
    int i = 0, hide = hide_discl;

    fi = fdopen(sock, "r");
    if (write(sock, query, strlen(query)) < 0)
	err_sys("write");
/* It has been reported this call breaks the client in some situations. Why?
    if (shutdown(sock, 1) < 0)
	err_sys("shutdown");
*/
    while (fgets(buf, 200, fi)) {	/* XXX errors? */
	if (hide == 1) {
	    if (strncmp(buf, hide_strings[i+1], strlen(hide_strings[i+1]))==0)
		hide = 2;	/* stop hiding */
	    continue;		/* hide this line */
	}
	if (hide == 0) {
	    for (i = 0; hide_strings[i] != NULL; i += 2) {
		if (strncmp(buf, hide_strings[i], strlen(hide_strings[i]))==0){
		    hide = 1;	/* start hiding */
		    break;
		}
	    }
	    if (hide == 1)
		continue;	/* hide the first line */
	}
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
		do_query(fd, nq);
		closeconn(fd);
		continue;
	    }
	}
#endif
	for (p = buf; *p && *p != '\r' && *p != '\n'; p++);
	*p = '\0';
	fprintf(stdout, "%s\n", buf);
    }
    if (ferror(fi))
	err_sys("fgets");

    if (hide == 1)
	err_quit(_("Catastrophic error: disclaimer text has been changed.\n"
		   "Please upgrade this program.\n"));
}

const char *query_crsnic(const int sock, const char *query)
{
    char *temp, buf[100], *ret = NULL;
    FILE *fi;

    temp = malloc(strlen(query) + 1 + 2 + 1);
    *temp = '=';
    strcpy(temp + 1, query);
    strcat(temp, "\r\n");

    fi = fdopen(sock, "r");
    if (write(sock, temp, strlen(temp)) < 0)
	err_sys("write");
    while (fgets(buf, 100, fi)) {
	/* If there are multiple matches only the server of the first record
	   is queried */
	if (strncmp(buf, "   Whois Server:", 16) == 0 && !ret) {
	    char *p, *q;

	    for (p = buf; *p != ':'; p++);	/* skip until colon */
	    for (p++; *p == ' '; p++);		/* skip colon and spaces */
	    ret = malloc(strlen(p) + 1);
	    for (q = ret; *p != '\n' && *p != '\r'; *q++ = *p++); /*copy data*/
	    *q = '\0';
	}
	fputs(buf, stdout);
    }
    if (ferror(fi))
	err_sys("fgets");

    free(temp);
    return ret;
}

int openconn(const char *server, const char *port)
{
    int fd;
#ifdef HAVE_GETADDRINFO
    int i;
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

    if ((i = getaddrinfo(server, port ? port : "whois", &hints, &res)) != 0)
	err_quit("getaddrinfo: %s", gai_strerror(i));
    for (ressave = res; res; res = res->ai_next) {
	if ((fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol))<0)
	    continue;		/* ignore */
	if (connect(fd, res->ai_addr, res->ai_addrlen) == 0)
	    break;		/* success */
	close(fd);
    }
    freeaddrinfo(ressave);

    if (!res)
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
    if (connect(fd, &saddr, sizeof(saddr)) < 0)
	err_sys("connect");
#endif
    return (fd);
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

    for (p = dom; *p != '\0'; p++); p--;	/* move to the last char */
    for (q = tld; *q != '\0'; q++); q--;
    while (p >= dom && q >= tld && tolower(*p) == *q) {	/* compare backwards */
	if (q == tld)				/* start of the second word? */
	    return 1;
	p--; q--;
    }
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
    fprintf(stderr, _(
"Usage: whois [OPTION]... OBJECT...\n\n"
"-a                     search all databases\n"
"-F                     fast raw output (implies -r)\n"
"-g SOURCE:FIRST-LAST   find updates from SOURCE from serial FIRST to LAST\n"
"-h HOST                connect to server HOST\n"
"-H                     hide legal disclaimers\n"
"-i ATTR[,ATTR]...      do an inverse lookup for specified ATTRibutes\n"
"-x                     exact match [RPSL only]\n"
"-l                     one level less specific lookup [RPSL only]\n"
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
"-t TYPE                request template for object of TYPE ('all' for a list)\n"
"-v TYPE                request verbose template for object of TYPE\n"
"-q [version|sources]   query specified server info [RPSL only]\n"
"-d                     return DNS reverse delegation objects too [RPSL only]\n"
"-K                     only primary keys are returned [RPSL only]\n"
"-V    --verbose        explain what is being done\n"
"      --help           display this help and exit\n"
"      --version        output version information and exit\n"
));
    exit(0);
}


/* Error routines */
void err_sys(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, ": %s\n", strerror(errno));
    va_end(ap);
    exit(2);
}

void err_quit(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputs("\n", stderr);
    va_end(ap);
    exit(2);
}

