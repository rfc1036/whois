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
    const unsigned char net;	/* bits 16-21 of the address */
    const char         *serv;
};

/* http://www.ripe.net/ripe/draft-documents/ipv6.html */
/* address bits 0-6 */
const struct ip6_del ip6_assign_rirs[] = {
    { 0x24, "whois.apnic.net" },
    { 0x28, "whois.afrinic.net" },
    { 0x2A, "whois.arin.net" },
    { 0x30, "whois.lacnic.net" },
    { 0x34, "whois.ripe.net" },
    { 0, NULL }
};

/* http://www.iana.org./assignments/ipv6-tla-assignments */
/* address bits 16 + 0-7 */
const struct ip6_del ip6_assign_misc[] = {
    { 0x02, "whois.apnic.net" },
    { 0x04, "whois.arin.net" },
    { 0x06, "whois.ripe.net" },
    { 0x08, "whois.ripe.net" },
    { 0x0A, "whois.ripe.net" },
    { 0x0C, "whois.apnic.net" },
    { 0x0E, "whois.apnic.net" },
/*  { 0x10, "" }, */
    { 0x12, "whois.lacnic.net" },
    { 0x14, "whois.ripe.net" },
    { 0x16, "whois.ripe.net" },
    { 0x18, "whois.arin.net" },
    { 0x1A, "whois.ripe.net" },
    { 0x1C, "whois.ripe.net" },
    { 0x1E, "whois.ripe.net" },
    { 0x20, "whois.ripe.net" },
    { 0x22, "whois.ripe.net" },
    { 0x24, "whois.ripe.net" },
    { 0x26, "whois.ripe.net" },
    { 0x28, "whois.ripe.net" },
    { 0x2A, "whois.ripe.net" },
    { 0x2C, "whois.ripe.net" },
    { 0x2E, "whois.ripe.net" },
    { 0x30, "whois.ripe.net" },
    { 0x32, "whois.ripe.net" },
    { 0x34, "whois.ripe.net" },
    { 0x36, "whois.ripe.net" },
    { 0x38, "whois.ripe.net" },
    { 0x3A, "whois.ripe.net" },
    { 0x40, "whois.ripe.net" },
    { 0x42, "whois.arin.net" },
    { 0x44, "whois.apnic.net" },
    { 0x46, "whois.ripe.net" },
    { 0x48, "whois.arin.net" },
    { 0x4A, "whois.ripe.net" },

    { 0x50, "whois.ripe.net" },
    { 0x52, "whois.ripe.net" },
    { 0x54, "whois.ripe.net" },
    { 0x56, "whois.ripe.net" },
    { 0x58, "whois.ripe.net" },
    { 0x5A, "whois.ripe.net" },
    { 0x5C, "whois.ripe.net" },
    { 0x5E, "whois.ripe.net" },

    { 0x80, "whois.apnic.net" },
    { 0x82, "whois.apnic.net" },
    { 0x84, "whois.apnic.net" },
    { 0x86, "whois.apnic.net" },
    { 0x88, "whois.apnic.net" },
    { 0x8A, "whois.apnic.net" },
    { 0x8C, "whois.apnic.net" },
    { 0x8E, "whois.apnic.net" },
    { 0x90, "whois.apnic.net" },
    { 0x92, "whois.apnic.net" },
    { 0x94, "whois.apnic.net" },
    { 0x96, "whois.apnic.net" },
    { 0x98, "whois.apnic.net" },
    { 0x9A, "whois.apnic.net" },
    { 0x9C, "whois.apnic.net" },
    { 0x9E, "whois.apnic.net" },
    { 0xA0, "whois.apnic.net" },
    { 0xA2, "whois.apnic.net" },
    { 0xA4, "whois.apnic.net" },
    { 0xA6, "whois.apnic.net" },
    { 0xA8, "whois.apnic.net" },
    { 0xAA, "whois.apnic.net" },
    { 0xAC, "whois.apnic.net" },
    { 0xAE, "whois.apnic.net" },
    { 0, NULL }
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

