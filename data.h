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
    "whois.oleane.net",
    "whois.denic.de",
    "rr.arin.net",		/* does not accept the old syntax */
    "whois.6bone.net",		/* 3.0.0b1 */
    "whois.aunic.net",
    "whois.connect.com.au",	/* 3.0.0b1 */
    "whois.nic.fr",
    "whois.nic.it",
    "whois.cw.net",
    "whois.telstra.net",
    "whois.nic.net.sg",
    "whois.metu.edu.tr",
    "whois.restena.lu",
    "rr.level3.net",		/* 3.0.0a13 */
    "whois.ripn.net",
    "whois.arnes.si",
    "www.registry.co.ug",
    "whois.nic.ir",
    "whois.nic.ck",
    NULL
};

/* servers which do not accept the new syntax */
const char *ripe_servers_old[] = {
    "whois.ra.net",
    "whois.domain.kg",
    "whois.nic.ch",
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
    "**************", "**************",				/* sg */
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
    "By submitting a WHOIS query,", "LACK OF A DOMAIN",		/* directNIC */
    "The Data in OnlineNIC", "\tBy starting this query",	/* OnlineNIC */
    "The data in Bulkregister.com", "you agree to abide", /* bulkregister */
    "The Data in Alldomains.com's", "By submitting this query,",/*alldomains*/
    "Interdomain's WHOIS", "DOES NOT SIGNIFY",
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
    unsigned long net;
    unsigned long mask;
    const char    *serv;
};

struct ip_del ip_assign[] = {
#include "ip_del.h"
    { 0, 0, NULL }
};

struct ip6_del {
    unsigned long net;		/* bits 16-22 of the address */
    const char    *serv;
};

/* http://www.iana.org./assignments/ipv6-tla-assignments */
struct ip6_del ip6_assign[] = {
    { 0x0200, "whois.apnic.net" },
    { 0x0400, "whois.arin.net" },
    { 0x0600, "whois.ripe.net" },
    { 0x0800, "whois.ripe.net" },
    { 0x0A00, "whois.ripe.net" },
    { 0x0C00, "whois.apnic.net" },
    { 0x0E00, "whois.apnic.net" },
/*  { 0x1000, "" }, */
    { 0x1200, "whois.lacnic.net" },
    { 0x1400, "whois.ripe.net" },
    { 0x1600, "whois.ripe.net" },
    { 0x1800, "whois.arin.net" },
    { 0x1A00, "whois.ripe.net" },
    { 0, NULL }
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

