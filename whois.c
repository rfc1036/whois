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
#include "config.h"
#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#endif
#ifdef HAVE_REGEXEC
#include <regex.h>
#endif
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

char *client_tag = (char *)IDSTRING;

#ifdef HAVE_GETOPT_LONG
static struct option longopts[] = {
    {"help",	no_argument,		NULL, 0  },
    {"version",	no_argument,		NULL, 1  },
    {"verbose",	no_argument,		NULL, 2  },
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
    int ch, nopar = 0;
    const char *server = NULL, *port = NULL;
    char *p, *q, *qstring, fstring[64] = "\0";

#ifdef ENABLE_NLS
    setlocale(LC_ALL, "");
    bindtextdomain(NLS_CAT_NAME, LOCALEDIR);
    textdomain(NLS_CAT_NAME);
#endif

    while ((ch = GETOPT_LONGISH(argc, argv, "acdFg:h:Hi:KlLmMp:q:rRs:St:T:v:V:x",
				longopts, 0)) > 0) {
	/* RIPE flags */
	if (strchr(ripeflags, ch)) {
	    for (p = fstring; *p; p++);
	    sprintf(p--, "-%c ", ch);
	    continue;
	}
	if (strchr(ripeflagsp, ch)) {
	    for (p = fstring; *p; p++);
	    sprintf(p--, "-%c %s ", ch, optarg);
	    if (ch == 't' || ch == 'v' || ch == 'q')
		nopar = 1;
	    continue;
	}
	/* program flags */
	switch (ch) {
	case 'h':
	    server = q = malloc(strlen(optarg) + 1);
	    for (p = optarg; *p && *p != ':'; *q++ = tolower(*p++));
	    if (*p == ':')
		port = p + 1;
	    *q = '\0';
	    break;
	case 'V':
	    client_tag = optarg;
	case 'H':
	    hide_discl = 0;	/* enable disclaimers hiding */
	    break;
	case 'p':
	    port = optarg;
	    break;
	case 2:
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

    /* -v or -t has been used */
    if (!server && !*qstring)
	server = "whois.ripe.net";

#ifdef CONFIG_FILE
    if (!server) {
	server = match_config_file(qstring);
	if (verb && server)
	    printf(_("Using server %s.\n"), server);
    }
#endif

    if (!server) {
	char *tmp;
	tmp = normalize_domain(qstring);
	server = whichwhois(tmp);
	free(tmp);
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
	    case 4:
		if (verb)
		    puts(_("Connecting to whois.crsnic.net."));
		sockfd = openconn("whois.crsnic.net", NULL);
		server = query_crsnic(sockfd, qstring);
		closeconn(sockfd);
		if (!server)
		    exit(0);
		printf(_("\nFound crsnic referral to %s.\n\n"), server);
		break;
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

    exit(0);
}

#ifdef CONFIG_FILE
const char *match_config_file(const char *s)
{
    FILE *fp;
    char buf[512];
    static const char delim[] = " \t";
#ifdef HAVE_REGEXEC
    regex_t re;
#endif

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
#endif

	for (p = buf; *p; p++)
	    if (*p == '\n')
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
	i = regcomp(&re, pattern, REG_EXTENDED|REG_ICASE|REG_NOSUB);
	if (i != 0) {
	    char m[1024];
	    regerror(i, &re, m, sizeof(m));
	    err_quit("Invalid regular expression '%s': %s", pattern, m);
	}

	i = regexec(&re, s, 0, NULL, 0);
	if (i == 0) {
	    regfree(&re);
	    return strdup(server);
	}
	if (i != REG_NOMATCH) {
	    char m[1024];
	    regerror(i, &re, m, sizeof(m));
	    err_quit("regexec: %s",  m);
	}
	regfree(&re);
#else
	if (domcmp(s, pattern))
	    return strdup(server);
#endif
    }
    return NULL;
}
#endif

const char *whichwhois(const char *s)
{
    unsigned long ip;
    unsigned int i;

    /* IPv6 address */
    if (strchr(s, ':')) {
	if (strncmp(s, "2001:2", 6) == 0 ||	/* XXX ugly hack! */
	    strncmp(s, "2001:02", 6) == 0 ||
	    strncasecmp(s, "2001:A",  6) == 0 ||
	    strncasecmp(s, "2001:0A", 6) == 0 ||
	    strncasecmp(s, "2001:C",  6) == 0 ||
	    strncasecmp(s, "2001:0C", 6) == 0)
	    return "whois.apnic.net";
	if (strncmp(s, "2001:4", 6) == 0 ||
	    strncmp(s, "2001:04", 6) == 0)
	    return "whois.arin.net";
	if (strncmp(s, "2001:6", 6) == 0 ||
	    strncmp(s, "2001:06", 6) == 0 ||
	    strncmp(s, "2001:8", 6) == 0 ||
	    strncmp(s, "2001:08", 6) == 0)
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

	for (p = s; *p; p++);			/* go to the end of s */
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

    if (asn > 28671)
	puts(_("Unknown AS number. Please upgrade this program."));
    else for (i = 0; aslist[i].serv; i++)
	if (asn >= aslist[i].first && asn <= aslist[i].last)
	    return aslist[i].serv;
    return "whois.arin.net";
}

char *queryformat(const char *server, const char *flags, const char *query)
{
    char *buf;
    int i, isripe = 0;

    /* +10 for CORE; +2 for \r\n; +1 for NULL */
    buf = malloc(strlen(flags) + strlen(query) + strlen(client_tag) + 4
	    + 10 + 2 + 1);
    *buf = '\0';
    for (i = 0; ripe_servers[i]; i++)
	if (strcmp(server, ripe_servers[i]) == 0) {
	    strcat(buf, "-V ");
	    strcat(buf, client_tag);
	    strcat(buf, " ");
	    isripe = 1;
	    break;
	}
    if (!isripe)
	for (i = 0; ripe_servers_old[i]; i++)
	    if (strcmp(server, ripe_servers_old[i]) == 0) {
		strcat(buf, "-V");
		strcat(buf, client_tag);
		strcat(buf, " ");
		isripe = 1;
		break;
	    }
    if (*flags) {
	if (!isripe && strcmp(server, "whois.corenic.net") != 0)
	    puts(_("Warning: RIPE flags used with a traditional server."));
	strcat(buf, flags);
    }
    if (!isripe && strcmp(server, "whois.nic.mil") == 0 &&
	    strncasecmp(query, "AS", 2) == 0 &&
	    query[2] >= '0' && query[2] <= '9')
	sprintf(buf, "AS %s", query + 2);	/* fix query for DDN */
    else if (!isripe && strcmp(server, "whois.corenic.net") == 0)
	sprintf(buf, "--machine %s", query);	/* machine readable output */
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
    char buf[2000], *p;
    FILE *fi;
    int i = 0, hide = hide_discl;

    fi = fdopen(sock, "r");
    if (write(sock, query, strlen(query)) < 0)
	err_sys("write");
/* Using shutdown breaks the buggy RIPE server.
    if (shutdown(sock, 1) < 0)
	err_sys("shutdown");
*/
    while (fgets(buf, sizeof(buf), fi)) {
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
    fclose(fi);

    if (hide == 1)
	err_quit(_("Catastrophic error: disclaimer text has been changed.\n"
		   "Please upgrade this program.\n"));
}

const char *query_crsnic(const int sock, const char *query)
{
    char *temp, buf[2000], *ret = NULL;
    FILE *fi;
    int state = 0;

    temp = malloc(strlen(query) + 1 + 2 + 1);
    *temp = '=';
    strcpy(temp + 1, query);
    strcat(temp, "\r\n");

    fi = fdopen(sock, "r");
    if (write(sock, temp, strlen(temp)) < 0)
	err_sys("write");
    while (fgets(buf, sizeof(buf), fi)) {
	/* If there are multiple matches only the server of the first record
	   is queried */
	if (state == 0 && strncmp(buf, "   Domain Name:", 15) == 0)
	    state = 1;
	if (state == 1 && strncmp(buf, "   Whois Server:", 16) == 0) {
	    char *p, *q;

	    for (p = buf; *p != ':'; p++);	/* skip until colon */
	    for (p++; *p == ' '; p++);		/* skip colon and spaces */
	    ret = malloc(strlen(p) + 1);
	    for (q = ret; *p != '\n' && *p != '\r'; *q++ = *p++); /*copy data*/
	    *q = '\0';
	    state = 2;
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
    int err;
    struct addrinfo hints, *res, *ai;
#else
    struct hostent *hostinfo;
    struct servent *servinfo;
    struct sockaddr_in saddr;
#endif

#ifdef HAVE_GETADDRINFO
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((err = getaddrinfo(server, port ? port : "whois", &hints, &res)) != 0)
	err_quit("getaddrinfo: %s", gai_strerror(err));
    for (ai = res; ai; ai = ai->ai_next) {
	if ((fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0)
	    continue;		/* ignore */
	if (connect(fd, (struct sockaddr *)ai->ai_addr, ai->ai_addrlen) == 0)
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
    if (connect(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
	err_sys("connect");
#endif
    return fd;
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

    for (p = dom; *p; p++); p--;	/* move to the last char */
    for (q = tld; *q; q++); q--;
    while (p >= dom && q >= tld && tolower(*p) == *q) {	/* compare backwards */
	if (q == tld)			/* start of the second word? */
	    return 1;
	p--; q--;
    }
    return 0;
}

char *normalize_domain(const char *dom)
{
    char *p, *ret;

    ret = strdup(dom);
    for (p = ret; *p; p++); p--;	/* move to the last char */
    for (; *p == '.' || p == ret; p--)	/* eat trailing dots */
	*p = '\0';
    return ret;
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

/* http://www.ripe.net/ripe/docs/databaseref-manual.html */

void usage(void)
{
    fprintf(stderr, _(
"Usage: whois [OPTION]... OBJECT...\n\n"
"-l                     one level less specific lookup [RPSL only]\n"
"-L                     find all Less specific matches\n"
"-m                     find first level more specific matches\n"
"-M                     find all More specific matches\n"
"-c                     find the smallest match containing a mnt-irt attribute\n"
"-x                     exact match [RPSL only]\n"
"-d                     return DNS reverse delegation objects too [RPSL only]\n"
"-i ATTR[,ATTR]...      do an inverse lookup for specified ATTRibutes\n"
"-T TYPE[,TYPE]...      only look for objects of TYPE\n"
"-K                     only primary keys are returned [RPSL only]\n"
"-r                     turn off recursive lookups for contact information\n"
"-R                     force to show local copy of the domain object even\n"
"                       if it contains referral\n"
"-a                     search all databases\n"
"-s SOURCE[,SOURCE]...  search the database from SOURCE\n"
"-g SOURCE:FIRST-LAST   find updates from SOURCE from serial FIRST to LAST\n"
"-t TYPE                request template for object of TYPE ('all' for a list)\n"
"-v TYPE                request verbose template for object of TYPE\n"
"-q [version|sources|types]  query specified server info [RPSL only]\n"
"-F                     fast raw output (implies -r)\n"
"-h HOST                connect to server HOST\n"
"-p PORT                connect to PORT\n"
"-H                     hide legal disclaimers\n"
"      --verbose        explain what is being done\n"
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

