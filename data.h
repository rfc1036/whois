const char *ripeflags="acFLmMrRS";
const char *ripeflagsp="gisTtv";

const char *ripe_servers[] = {
    "whois.ripe.net",
    "whois.ra.net",
    "whois.apnic.net",
    "whois.mci.net",
    "whois.isi.edu",
    "whois.nic.it",
    "whois.6bone.net",
    "whois.ans.net",
    NULL
};

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
    unsigned long int	net;
    unsigned long int	mask;
    const char		*serv;
};

struct ip_del ip_assign[] = {
#include "ip_del.h"
    { 0, 0, NULL }
};

const char *tld_serv[] = {
#include "tld_serv.h"
    NULL,	NULL
};

