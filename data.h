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
    "whois.telstra.net",
    "whois.nic.net.sg",
    "whois.metu.edu.tr",
    "whois.restena.lu",
    "rr.level3.net",		/* 3.0.0a13 */
    "whois.arnes.si",
    "www.registry.co.ug",
    "whois.nic.ir",
    NULL
};

/* servers which do not accept the new syntax */
const char *ripe_servers_old[] = {
    "whois.ra.net",
    "whois.nic.it",
    "whois.ans.net",
    "whois.cw.net",
    "whois.ripn.net",
    "whois.nic.ck",
    "whois.domain.kg",
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

const char *hide_strings[] = {
    "The Data in the VeriSign", "terms at any time.",
    "The data in Register", "By submitting",
    " The data contained in Dotster", "Please limit your",
    "This whois service currently only", "top-level domains.",
    "Signature Domains' Whois Service", "agree to abide by the above",
    "Access to ASNIC", "by this policy.",
    "* Copyright (C) 1998 by SGNIC", "* modification.",
    "The Data in Gabia", "you agree to abide",
    "NeuLevel, Inc., the Registry Operator", "whatsoever, you agree",
    "NOTICE: Access to .INFO WHOIS", "time. By submitting",
    "Disclaimer: The Global Name Registry", "for any commercial",
    "Access to America Online", "time. By accessing",
    "Access and use restricted", "http://www.icann", /* GANDI */
    "NeuStar, Inc., the Registry", "whatsoever, you agree", /* us */
    NULL, NULL
};

const char *nic_handles[] = {
    "net-",	"whois.arin.net",
    "netblk-",	"whois.arin.net",
    "asn-",	"whois.arin.net",
    "lim-",	"whois.ripe.net",
    "coco-",	"whois.corenic.net",
    "coho-",	"whois.corenic.net",
    "core-",	"whois.corenic.net",
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

