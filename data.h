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
    "whois.afrinic.net",
    "rr.arin.net",		/* does not accept the old syntax */
    "whois.6bone.net",		/* 3.0.0b1 */
    "whois.connect.com.au",	/* 3.0.0b1 */
    "whois.nic.fr",
    "whois.telstra.net",
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
    "NOTICE AND TERMS OF USE: You", "",				/* NetSol */
    "TERMS OF USE: You are not", "",				/* crsnic */
    "NOTICE: Access to .ORG WHOIS", "",
    "NOTICE: Access to .INFO WHOIS", "",
    "NOTICE: Access to the .aero", "",
    "This Registry database contains ONLY .EDU", "type: help",	/* edu */
    "% .eu Whois Server", "% of the database",
    "The data in Register", "",				    /* Register.Com */
    "The Data in the Tucows", "RECORD DOES NOT",
    " The data contained in the WHOIS", "",			/* DOTSTER */
    "This whois service currently only", "top-level domains.",
    "Signature Domains' Whois Service", "agree to abide by the above",
    "Access to ASNIC", "by this policy.",			/* as */
    "The Data in Gabia", "you agree to abide",
    "The data contained in Go Daddy", "is not the registrant",
    "Disclaimer: The Global Name Registry", "for any commercial",
    "Access to America Online", "time. By accessing",		/* AOL */
    "% Access and use restricted", "",				/* GANDI */
    "% The data in the WHOIS database of Schlund", "",
    "NeuStar, Inc., the Registry", "rules.  For details",	/* us */
    "The data in this whois database is", "",			/* enom */
    "By submitting a WHOIS query, you agree you will", "LACK OF A DOMAIN",		/* directNIC */
    "The Data in Moniker.Com", "",
    "The Data in OnlineNIC", "    By starting this query",
    "The data in Bulkregister", "",
    "Interdomain's WHOIS", "DOES NOT SIGNIFY",
    "The Data provided by Stargate Holdings", "(2) enable any",
    "; This data is provided by domaindiscount24.com", "",
    "%% BookMyName Whois", "%% this policy",
    "The .coop registry WHOIS", "VERIFICATION, NOR DO",
    "Tralliance, Inc., the Registry", "",			/* travel */
    "NOTICE: Access to the domains information", "",		/* CORE */
    "%% puntCAT Whois Server", "%% any time.",
    NULL, NULL
};

const char *nic_handles[] = {
    "net-",	"whois.arin.net",
    "netblk-",	"whois.arin.net",
    "poem-",	"whois.ripe.net",
    "form-",	"whois.ripe.net",
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

struct as32_del {
    const unsigned long first;
    const unsigned long last;
    const char         *serv;
};

const struct as32_del as32_assign[] = {
#include "as32_del.h"
    { 0, 0, NULL }
};

const char *tld_serv[] = {
#include "tld_serv.h"
    NULL,	NULL
};

