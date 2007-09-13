/* 6bone referto: extension */
#define REFERTO_FORMAT	"%% referto: whois -h %255s -p %15s %1021[^\n\r]"

/* String sent to RIPE servers - MUST NOT BE LONGER THAN FIVE CHARACTERS! */
/* Do *NOT* change it if you don't know what you are doing! */
#define IDSTRING "Md4.7"

#define HIDE_DISABLED  -2
#define HIDE_UNSTARTED -1

/* prototypes */
const char *whichwhois(const char *);
const char *match_config_file(const char *);
const char *whereas(const unsigned short);
const char *whereas32(const unsigned long);
char *queryformat(const char *, const char *, const char *);
int hide_line(int *hiding, const char *const line);
const char *do_query(const int, const char *);
const char *query_crsnic(const int, const char *);
const char *query_pir(const int, const char *);
int openconn(const char *, const char *);
void usage(void);
void alarm_handler(int);
void sighandler(int);
unsigned long myinet_aton(const char *);
unsigned long asn32_to_long(const char *);
int isasciidigit(const char);
int domcmp(const char *, const char *);
int domfind(const char *, const char *[]);
char *normalize_domain(const char *);
char *convert_6to4(const char *);
char *convert_teredo(const char *);
const char *handle_query(const char *server, const char *port,
		   const char *qstring, const char *fstring);
void split_server_port(const char *const input, const char **server,
		       const char **port);

void err_quit(const char *,...);
void err_sys(const char *,...);


/* flags for RIPE-like servers */
const char *ripeflags="abBcdFGKlLmMrRSx";
const char *ripeflagsp="gisTtvq";

