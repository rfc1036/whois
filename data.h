/*
 * RIPE-like servers.
 * All of them do not understand -V2.0Md with the exception of RA and RIPN.
 */

/* servers which accept the new syntax (-V XXn.n) */
const char *ripe_servers[] = {
    "whois.ripe.net",
    "whois.apnic.net",
    "whois.afrinic.net",
    "rr.arin.net",		/* does not accept the old syntax */
    "whois.connect.com.au",	/* 3.0.0b1 */
    "whois.nic.fr",
    "whois.restena.lu",
    "rr.level3.net",		/* 3.0.0a13 */
    "whois.ripn.net",
    "whois.arnes.si",
    "whois.nic.ir",
    "whois.ra.net",
    "whois.bgpmon.net",
    NULL
};

const char *hide_strings[] = {
    "The data in Networksolutions.com's WHOIS database", NULL,
    /* Some registrars like .wang copied the first paragraph of this
     * disclaimer, so the detection here needs to be split in two parts. */
    "TERMS OF USE: You are not authorized", NULL,	/* crsnic */
    "The data in Register.com's WHOIS database", NULL,
    "The Data in the Tucows Registrar WHOIS database", NULL,
    "The data in NameSecure.com's WHOIS database", NULL,
    "The Data in Gabia's WHOIS database", NULL,
    "The data contained in GoDaddy.com", NULL,
    "Personal data access and use are governed by French", NULL, /* GANDI */
    "The data in this whois database is provided to you", NULL,	/* enom */
    "; Please register your domains at; http://www.", NULL, /* key-systems.net */
    "%% NOTICE: Access to this information is provided", NULL, /* bookmyname.com */
    "% NOTICE: Access to the domains information", NULL, /* CORE */
    "The Data in MarkMonitor.com's", NULL, /* MarkMonitor */
    "Corporation Service Company(c) (CSC)  The Trusted Partner", "Register your domain name at", /* CSC */
    "The data in Networksolutions.com's", NULL,		/* Networksolutions */
    "# Welcome to the OVH WHOIS Server", "", /* ovh */
    "TERMS OF USE OF MELBOURNE IT WHOIS DATABASE", NULL,
    "The data contained in this Registrar's Whois", NULL, /* wildwestdomains.com */
    "The data in the FastDomain Inc. WHOIS database", NULL,

    /* gTLDs */
    "Access to .AERO WHOIS information", "",
    "DotAsia WHOIS LEGAL STATEMENT", "integrity of the database.",
    "The .coop registry WHOIS", "VERIFICATION, NOR DO",
    "%% puntCAT Whois Server", "%% any time.",
    "This Registry database contains ONLY .EDU", "type: help",	/* edu */
    "Access to AFILIAS WHOIS information is provided", NULL,	/* .info */
    "mTLD WHOIS LEGAL STATEMENT", "integrity of the database.",	/* .mobi */
    "Access to Public Interest Registry WHOIS information", NULL, /* .org */
    "Access to .PRO REGISTRY WHOIS information", "",
    "Telnic, Ltd., the Registry Operator for .TEL", NULL,
    "Tralliance, Inc., the Registry Operator for .travel", NULL,
    "Access to .XXX ICM REGISTRY WHOIS", NULL,			/* .xxx */

    /* new gTLDs */
    "Terms of Use: Users accessing the Donuts WHOIS", NULL,
    "Terms of Use: Users accessing the United TLD WHOIS", NULL,
    "Access to WHOIS information is provided", NULL,		/* Afilias */
    "The  WHOIS information provided on this page", NULL, /* uniregistry.net */
    "The whois information provided on this site", "",	/* mm-registry.com */
    "; This data is provided by ", NULL,		/* ksregistry.net */
    "This whois service is provided by CentralNic Ltd", "",
    ".Club Domains, LLC, the Registry Operator", NULL,
    "% Except for agreed Internet operational purposes", NULL,	/* .berlin */
    "TERMS OF USE: The information in the Whois database", NULL, /* .wang */
    "The WHOIS service offered by Neustar, Inc, on behalf", NULL,
    "The WHOIS service offered by the Registry Operator", NULL, /* .science */

    /* ccTLDs */
    "Access to CCTLD WHOIS information is provided", "",	/* Afilias */
    "This WHOIS information is provided", NULL,			/* as */
    "% The WHOIS service offered by DNS Belgium", "",		/* be */
    "%   (c) 2015 NIC Costa Rica", "",				/* cr */
    "% The WHOIS service offered by EURid", "% of the database", /* eu */
    "% WHOIS LEGAL STATEMENT AND TERMS & CONDITIONS", NULL,	/* sx */
    "; The data in the WHOIS database of KSregistry GmbH", "",	/* vg */
    "NeuStar, Inc., the Registry Administrator for .US", NULL,

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

const char *nic_handles_post[] = {
#include "nic_handles.h"
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

