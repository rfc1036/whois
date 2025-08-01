/* SPDX-License-Identifier: GPL-2.0-or-later */

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
    "rr.level3.net",		/* 3.0.0a13 */
    "rr.ntt.net",
    "whois.tcinet.ru",
    "whois.ripn.net",
    "whois.register.si",
    "whois.nic.ir",
    NULL
};

struct server_referral_handler {
    const char *name;
    void (*handler)(char **referral_server, const char *buf);
};

const struct server_referral_handler server_referral_handlers[] = {
    { "whois.apnic.net",		find_referral_server_apnic },
    { "whois.arin.net",			find_referral_server_arin },
    { "whois.iana.org",			find_referral_server_iana },
    { "\x04",				find_referral_server_verisign },
    { "\x08",				find_referral_server_recursive },
    { NULL, NULL }
};

const char *hide_strings[] = {
    "The data in Networksolutions.com's WHOIS database", NULL,
    /* Some registrars like .wang copied the first paragraph of this
     * disclaimer, so the detection here needs to be split in two parts. */
    "TERMS OF USE: You are not authorized", NULL,	/* crsnic */
    "The data in Register.com's WHOIS database", NULL,
    "The Data in the Tucows Registrar WHOIS database", NULL,
    "TERMS OF USE: The Data in Gabia' WHOIS", NULL,
    "The data contained in GoDaddy.com", NULL,
    "Personal data access and use are governed by French", NULL, /* GANDI */
    "The data in this whois database is provided to you", NULL,	/* enom */
    "Please register your domains at; http://www.", NULL, /* key-systems.net */
    "%% NOTICE: Access to this information is provided", NULL, /* bookmyname.com */
    "NOTICE: Access to the domain name's information", NULL, /* CORE */
    "The data in MarkMonitor’s WHOIS", NULL,		/* MarkMonitor */
    "Corporation Service Company(c) (CSC)  The Trusted Partner", "Register your domain name at", /* CSC */
    "The data in Networksolutions.com's", NULL,		/* Networksolutions */
    "# Welcome to the OVH WHOIS Server", "", /* ovh */
    "TERMS OF USE OF MELBOURNE IT WHOIS DATABASE", NULL,
    "The data contained in this Registrar's Whois", NULL, /* wildwestdomains.com */
    "The data in the FastDomain Inc. WHOIS database", NULL,

    /* gTLDs */
    "Access to WHOIS information is provided", NULL,
    "This Registry database contains ONLY .EDU", "domain names.", /* edu */
    "Access to AFILIAS WHOIS information is provided", NULL,	/* .info */
    "Access to Public Interest Registry WHOIS information", NULL, /* .org */
    "Telnames Limited, the Registry Operator for", NULL,
    "Tralliance, Inc., the Registry Operator for .travel", NULL,
    "The data in this record is provided by", NULL,	/* .xxx */

    /* new gTLDs */
    "Terms of Use: Donuts Inc. provides", NULL,
    "Access to WHOIS information is provided", NULL,		/* Afilias */
    "TERMS OF USE: You  are  not  authorized", NULL, /* uniregistry.net */
    "The Whois and RDAP services are provided by CentralNic", "",
    ".Club Domains, LLC, the Registry Operator", NULL,
    "% Except for agreed Internet operational purposes", NULL,	/* .berlin */
    "TERMS OF USE: The information in the Whois database", NULL, /* .wang */
    "The WHOIS service offered by Neustar, Inc, on behalf", NULL,
    "The WHOIS service offered by the Registry Operator", NULL, /* .science */

    /* ccTLDs */
    "Access to CCTLD WHOIS information is provided", "",	/* Afilias */
    "This WHOIS information is provided", NULL,			/* as */
    "% The WHOIS service offered by DNS Belgium", "",		/* be */
    ".CO Internet, S.A.S., the Administrator", NULL,		/* co */
    "%  *The information provided",
	"% https://www.nic.cr/iniciar-sesion/?next=/mi-cuenta/",/* cr */
    "% The WHOIS service offered by EURid", "% of the database", /* eu */
    "Access to .IN WHOIS information", NULL,			/* in */
    "access to .in whois information", NULL,		/* in registar */
    "% Use of CIRA's WHOIS service is governed by the Terms of Use in its Legal", NULL,	/* sx */
    "Terms of Use: Access to WHOIS information", NULL,		/* vc */
    "The Service is provided so that you may look", "We may discontinue",/*vu*/
    "NeuStar, Inc., the Registry Administrator for .US", NULL,
    "; This data is provided ", NULL,			/* whois.1api.net */

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
    const unsigned long first;
    const unsigned long last;
    const char          *serv;
};

const struct as_del as_assign[] = {
#include "as_del.h"
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

