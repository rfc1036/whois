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
    "whois.bgpmon.net",
    NULL
};

const char *hide_strings[] = {
    "NOTICE AND TERMS OF USE: You", "",				/* NetSol */
    "NOTICE: The expiration date", "reserves the right",	/* crsnic */
    "The data in Register", "",				    /* Register.Com */
    "The Data in the Tucows", "RECORD DOES NOT",
    "The information in this whois database", "",		/* DOTSTER */
    "This whois service currently only", "top-level domains.",	/* NameSecure */
    "The Data in Gabia", "you agree to abide",
    "The data contained in GoDaddy.com", "is not the registrant",
    "Disclaimer: The Global Name Registry", "for any commercial",
    "Access to America Online", "time. By accessing",		/* AOL */
    "# Access and use restricted", "",				/* GANDI */
    "% The data in the WHOIS database of 1&1 Internet", "",
    "The data in this whois database is", NULL, /* enom, activeregistrar.com */
    "The Data in Moniker's WHOIS database", "of Moniker.",
    "The Data in OnlineNIC", "    By starting this query",
    "Interdomain's WHOIS", "DOES NOT SIGNIFY",
    "The Data provided by Stargate Holdings", "(2) enable any",
    "; This data is provided by domaindiscount24.com", "",
    "%% NOTICE: Access to this information is provided", "%% By submitting", /* bookmyname.com */
    "% NOTICE: Access to the domains information", "% this query", /* CORE */
    "The Data in MarkMonitor.com's", "--", /* MarkMonitor */
    "Corporation Service Company(c) (CSC)  The Trusted Partner", "Register your domain name at", /* CSC */
    "The data in Networksolutions.com's", "By submitting this query", /* Networksolutions */
    "% Copyright (c)2003 by Deutsche Telekom AG", "% DOMAIN full", /* Deutsche Telekom  */
    "# Welcome to the OVH WHOIS Server", "# soumettant une", /* ovh */

    /* gTLDs */
    "Access to .AERO WHOIS information", "",
    "DotAsia WHOIS LEGAL STATEMENT", "integrity of the database.",
    "The .coop registry WHOIS", "VERIFICATION, NOR DO",
    "%% puntCAT Whois Server", "%% any time.",
    "This Registry database contains ONLY .EDU", "type: help",	/* edu */
    "Access to INFO WHOIS information is provided", "",		/* Afilias */
    "mTLD WHOIS LEGAL STATEMENT", "integrity of the database.",	/* .mobi */
    "Access to .ORG WHOIS information", "",
    "Access to RegistryPro's Whois", "All rights",		/* .pro */
    "Telnic, Ltd., the Registry Operator", "(b) harass any person;", /* .tel */
    "Tralliance, Inc., the Registry", "",			/* .travel */
    "Access to .XXX ICM REGISTRY WHOIS", "",			/* .xxx */

    /* ccTLDs */
    "Access to CCTLD WHOIS information is provided", "",	/* Afilias */
    "Access to ASNIC", "by this policy.",			/* as */
    "% The WHOIS service offered by DNS.be", "% protect the privacy", /* be */
    "% The WHOIS service offered by EURid", "% of the database", /* eu */
    "% WHOIS LEGAL STATEMENT AND TERMS & CONDITIONS", "",	/* sx */
    "NeuStar, Inc., the Registry", "OF THE AVAILABILITY",	/* us */

    NULL, NULL
};

const char *nic_handles[] = {
    "net-",	"whois.arin.net",
    "netblk-",	"whois.arin.net",
    "poem-",	"whois.ripe.net",
    "form-",	"whois.ripe.net",
    "pgpkey-",	"whois.ripe.net",
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
#include "ip_del_recovered.h"
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

const char *new_gtlds[] = {
#include "new_gtlds.h"
    NULL
};

const char *tld_serv[] = {
#include "tld_serv.h"
    NULL,	NULL
};

#ifdef HAVE_ICONV
struct server_charset {
    const char *name;
    const char *charset;
    const char *options;
};

const struct server_charset servers_charset[] = {
#include "servers_charset.h"
    { NULL, NULL, NULL }
};
#endif

