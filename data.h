/*
 * RIPE-like servers.
 * All of them do not understand -V2.0Md with the exception of RA and RIPN.
 * 6bone-derived servers will accept the flag with a warning (the flag must
 * match /^V [a-zA-Z]{1,4}\d+[\d\.]{0,5}$/).
 */

/* servers which accept the new syntax (-V XXn.n) */
const char *ripe_servers[] = {
    "whois.ripe.net",
    "whois.apnic.net",
    "whois.denic.de",
    "rr.arin.net",		/* does not accept the old syntax */
    "whois.6bone.net",		/* 3.0.0b1 */
    "whois.connect.com.au",	/* 3.0.0b1 */
    "whois.nic.fr",
    "whois.nic.it",
    "whois.telstra.net",
    "whois.metu.edu.tr",
    "whois.restena.lu",
    "rr.level3.net",		/* 3.0.0a13 */
    "whois.ripn.net",
    "whois.arnes.si",
    "www.registry.co.ug",
    "whois.nic.ir",
    "whois.nic.ck",
    "whois.ra.net",
    NULL
};

const char *hide_strings[] = {
    "NOTICE AND TERMS OF USE: You", "Network Solutions reserves",/* Verisign */
    "NOTICE: The expiration date", "Registrars.",		/* crsnic */
    "NOTICE: Access to .ORG WHOIS", "time. By submitting",	/* org */
    "NOTICE: Access to .INFO WHOIS", "time. By submitting",	/* info */
    "This Registry database contains ONLY .EDU", "type: help",	/* edu */
    "The data in Register", "By submitting",		    /* REGISTER.COM */
    "The Data in the Tucows", "RECORD DOES NOT",		/* OPENSRS */
    " The data contained in the WHOIS", "Please limit your",	/* DOTSTER */
    "This whois service currently only", "top-level domains.",
    "Signature Domains' Whois Service", "agree to abide by the above",
    "Access to ASNIC", "by this policy.",			/* as */
    "The Data in Gabia", "you agree to abide",
    "The data contained in Go Daddy", "is not the registrant",	/* Go Daddy */
    "Disclaimer: The Global Name Registry", "for any commercial",
    "Access to America Online", "time. By accessing",		/* AOL */
    "% Access and use restricted", "% http://www.icann",	/* GANDI */
    "NeuStar, Inc., the Registry", "rules.  For details",	/* us */
#if 0
    // This must be disabled because whois.bizcn.com uses a similar text
    "The data in this whois", "using our Whois information",	/* enom */
#endif
    "By submitting a WHOIS query, you agree you will", "LACK OF A DOMAIN",		/* directNIC */
    "The Data in Moniker.com", "this query, you agree",
    "The Data in OnlineNIC", "    By starting this query",	/* OnlineNIC */
    "The data in Bulkregister.com", "you agree to abide", /* bulkregister */
    "The Data in Alldomains.com's", "By submitting this query,",/*alldomains*/
    "Interdomain's WHOIS", "DOES NOT SIGNIFY",
    "The Data provided by Stargate.com", "(2) enable any",
    "; This data is provided by dd24", "; By submitting this query",
    NULL, NULL
};

const char *nic_handles[] = {
    "net-",	"whois.arin.net",
    "netblk-",	"whois.arin.net",
    "lim-",	"whois.ripe.net",
#if 0
    // commented until somebody will explain the query format for these
    "coco-",	"whois.corenic.net",
    "coho-",	"whois.corenic.net",
    "core-",	"whois.corenic.net",
#endif
    "denic-",	"whois.denic.de",
    /* RPSL objects */
    "as-",	"whois.ripe.net",
    "rs-",	"whois.ripe.net",
    "rtrs-",	"whois.ripe.net",
    "fltr-",	"whois.ripe.net",
    "prng-",	"whois.ripe.net",
    NULL,	NULL
};

struct ip_del {
    const unsigned long net;
    const unsigned long mask;
    const char         *serv;
};

const struct ip_del ip_assign[] = {
#include "ip_del.h"
    { 0, 0, NULL }
};

struct ip6_del {
    const unsigned long  net;
    const unsigned short masklen;
    const char          *serv;
};

const struct ip6_del ip6_assign[] = {
#include "ip6_del.h"
    { 0, 0, NULL }
};

struct as_del {
    const unsigned short first;
    const unsigned short last;
    const char          *serv;
};

const struct as_del as_assign[] = {
#include "as_del.h"
    { 0, 0, NULL }
};

const char *tld_serv[] = {
#include "tld_serv.h"
    NULL,	NULL
};

