/* Identification string */
/* #define IDSTRING "-VMd" VERSION */
#define IDSTRING "-VwC2.0"

/* Size of the buffer where the query is built */
#define QUERYBUFSIZE 1024

/* Protocol data which could change */
/* First and last lines of the Internic disclaimer */
#define DISCL_BEGIN	"The Data in"
#define DISCL_END	"this query"

/* 6bone referto: extension */
#define REFERTO_FORMAT	"%% referto: whois -h %255s -p %15s %1023[^\n\r]"


/* system features */
#ifdef linux
# define HAVE_GNU_GETOPT
# define ENABLE_NLS
# if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 1
#  define HAVE_GETADDRINFO
# endif
#endif

#ifdef ENABLE_NLS
# define NLS_CAT_NAME   "whois"
# ifndef LOCALEDIR
#  define LOCALEDIR     "/usr/share/locale"
# endif
#endif


/* NLS stuff */
#ifdef ENABLE_NLS
# include <libintl.h>
# include <locale.h>
# define _(a) (gettext (a))
# ifdef gettext_noop
#  define N_(a) gettext_noop (a)
# else
#  define N_(a) (a)
# endif
#else
# define _(a) (a)
# define N_(a) a
#endif


/* If needed, disable GNU getopt "features" */
#ifdef HAVE_GNU_GETOPT
# define GETOPT(argc, argv, str) getopt((argc), (argv), "+" str)
#else
# define GETOPT(argc, argv, str) getopt((argc), (argv), (str))
#endif


/* prototypes */
const char *whichwhois(const char *);
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

void err_quit(const char *,...);
void err_sys(const char *,...);

