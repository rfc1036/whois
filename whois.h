/* 6bone referto: extension */
#define REFERTO_FORMAT	"%% referto: whois -h %255s -p %15s %1021[^\n\r]"

/* String sent to RIPE servers - ONLY FIVE CHARACTERS! */
/* Do *NOT* change it if you don't know what you are doing! */
#define IDSTRING "Md4.5"

/* prototypes */
const char *whichwhois(const char *);
const char *match_config_file(const char *);
const char *whereas(int, struct as_del []);
char *queryformat(const char *, const char *, const char *);
void do_query(const int, const char *);
const char *query_crsnic(const int, const char *);
int openconn(const char *, const char *);
void closeconn(const int);
void usage(void);
void sighandler(int);
unsigned long myinet_aton(const char *);
int domcmp(const char *, const char *);
int domfind(const char *, const char *[]);
char *normalize_domain(const char *);

void err_quit(const char *,...);
void err_sys(const char *,...);


/* flags for RIPE-like servers */
const char *ripeflags="acFKlLmMrRSx";
const char *ripeflagsp="gisTtvq";

