/*
 * RIPE-like servers.
 * All of them do not understand -V2.0Md with the exception of RA and RIPN.
 * 6bone-like servers will accept the flag with a warning (the flag must
 * match /^V [a-zA-Z]{1,4}\d+[\d\.]{0,5}$/).
 */
const char *ripe_servers[] = {
    /* will accept the new syntax (-V wp3.0) */
    "whois.ripe.net",
    "whois.apnic.net",
    "whois.6bone.net",		/* 3.0.0b1 */
    "whois.aunic.net",
    "whois.connect.com.au",	/* 3.0.0b1 */
    "whois.nic.fr",
    "whois.nic.net.sg",
    "whois.metu.edu.tr",
    /* end of servers accepting new syntax */
    "whois.nic.it",
    "whois.ans.net",
    "whois.ra.net",
    "whois.ripn.net",
    NULL
};

#if 0
const char *rwhois_servers[] = {
    "whois.isi.edu",		/* V-1.0B9.2 */
    "rwhois.rcp.net.pe",	/* V-1.5.3 */
    "ns.twnic.net",		/* V-1.0B9 */
    "dragon.seed.net.tw",	/* V-1.0B9.2 */
    NULL
};
#endif

const char *gtlds[] = {
    ".com",
    ".net",
    ".org",
    ".edu",
    NULL
};

const char *arin_nets[] = {
    "net-",
    "netblk-",
    "asn-",
    NULL,
};

struct ip_del {
    unsigned long net;
    unsigned long mask;
    const char    *serv;
};

struct ip_del ip_assign[] = {
#include "ip_del.h"
    { 0, 0, NULL }
};

struct as_del {
    unsigned short first;
    unsigned short last;
    const char     *serv;
};

struct as_del as_assign[] = {
#include "as_del.h"
    { 0, 0, NULL }
};

const char *tld_serv[] = {
#include "tld_serv.h"
    NULL,	NULL
};

