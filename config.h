/* Program version */
/* not for the inetutils version */
#define VERSION "4.5.4"

/* Configurable features */

/* 6bone referto: support */
#define EXT_6BONE

/* Always hide legal disclaimers */
#undef ALWAYS_HIDE_DISCL

/* Default server */
#define DEFAULTSERVER   "whois.internic.net"

/* not for the inetutils version */
#ifdef linux
# define ENABLE_NLS
# define HAVE_GETOPT_LONG
# if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 1
#  define HAVE_GETADDRINFO
# endif
#endif

