/* Program version */
/* not for the inetutils version */
#define VERSION "4.5.8"

/* Configurable features */

/* 6bone referto: support */
#define EXT_6BONE

/* Always hide legal disclaimers */
#undef ALWAYS_HIDE_DISCL

/* Default server */
#define DEFAULTSERVER   "whois.internic.net"

/* autoconf in cpp macros */
#ifdef linux
# define ENABLE_NLS
# define HAVE_GETOPT_LONG
# if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 1
#  define HAVE_GETADDRINFO
# endif
#endif

/* needs unistd.h */
#ifdef _ISO_CPP_14882_1998
/* Solaris 8 and better. What else? */
# define HAVE_GETADDRINFO
#endif

/* system features */
#ifdef ENABLE_NLS
# ifndef NLS_CAT_NAME
#  define NLS_CAT_NAME   "whois"
# endif
# ifndef LOCALEDIR
#  define LOCALEDIR     "/usr/share/locale"
# endif
#endif

#ifdef HAVE_GETOPT_LONG
# define GETOPT_LONGISH(c, v, o, l, i) getopt_long(c, v, o, l, i)
#else
# define GETOPT_LONGISH(c, v, o, l, i) getopt(c, v, o)
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

