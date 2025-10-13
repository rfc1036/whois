/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "utils.h"

#define HIDE_TO_THE_END  -3
#define HIDE_DISABLED    -2
#define HIDE_NOT_STARTED -1

/* prototypes */
int is_asn(const char *, int, const char *);
char *guess_server(const char *);
const char *match_config_file(const char *);
const char *whereas(const unsigned long);
char *queryformat(const char *, const char *, const char *);
int hide_line(int *hiding, const char *const line);
char *query_server(const char *, const char *, const char *);
char *query_verisign(const char *, const char *, const char *);
int openconn(const char *, const char *);
int connect_with_timeout(int, const struct sockaddr *, socklen_t, int);
void NORETURN usage(int error);
void NORETURN alarm_handler(int);
void NORETURN sighandler(int);
int japanese_locale(void);
unsigned long myinet_aton(const char *);
int isasciidigit(const char);
int endstrcaseeq(const char *, const char *);
int in_domain(const char *, const char *);
const char *is_new_gtld(const char *);
int domfind(const char *, const char *[]);
char *normalize_domain(const char *);
char *convert_6to4(const char *);
char *convert_teredo(const char *);
char *convert_inaddr(const char *);
char *convert_in6arpa(const char *);
int handle_query(const char *server, const char *port,
		   const char *qstring, const char *fstring);
void split_server_port(const char *const input, char **server, char **port);


/* flags for RIPE-like servers */
const char *ripeflags="abBcdFGKlLmMrRx";
const char *ripeflagsp="gisTtvq";

