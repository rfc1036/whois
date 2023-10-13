/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef WHOIS_UTILS_H
#define WHOIS_UTILS_H

/* Convenience macros */
#define streq(a, b) (strcmp(a, b) == 0)
#define strcaseeq(a, b) (strcasecmp(a, b) == 0)
#define strneq(a, b, n) (strncmp(a, b, n) == 0)
#define strncaseeq(a, b, n) (strncasecmp(a, b, n) == 0)

#define NOFAIL(ptr) do_nofail((ptr), __FILE__, __LINE__)

#ifndef AFL_MODE
# define AFL_MODE 0
#endif

/* Portability macros */
#ifdef __GNUC__
# define NORETURN __attribute__((noreturn))
#ifndef __clang__
# define MALLOC_FREE __attribute__((malloc(free)))
#else
# define MALLOC_FREE
#endif
# define NONNULL __attribute__((returns_nonnull))
#else
# define NORETURN
# define MALLOC_FREE
# define NONNULL
#endif

#ifndef AI_IDN
# define AI_IDN 0
#endif

#ifndef AI_ADDRCONFIG
# define AI_ADDRCONFIG 0
#endif

#ifdef HAVE_GETOPT_LONG
# define GETOPT_LONGISH(c, v, o, l, i) getopt_long(c, v, o, l, i)
#else
# define GETOPT_LONGISH(c, v, o, l, i) getopt(c, v, o)
#endif

#ifdef ENABLE_NLS
# include <libintl.h>
# include <locale.h>
# define _(a) (gettext(a))
# ifdef gettext_noop
#  define N_(a) gettext_noop(a)
# else
#  define N_(a) (a)
# endif
#else
# define _(a) (a)
# define N_(a) (a)
# define ngettext(a, b, c) ((c==1) ? (a) : (b))
#endif

#if defined IDN2_VERSION_NUMBER && IDN2_VERSION_NUMBER < 0x00140000
# define IDN2_NONTRANSITIONAL IDN2_NFC_INPUT
#endif

/* Prototypes */
void *MALLOC_FREE NONNULL do_nofail(void *ptr, const char *file, const int line)
;
char **merge_args(char *args, char *argv[], int *argc);

void NORETURN err_quit(const char *fmt, ...);
void NORETURN err_sys(const char *fmt, ...);

#endif
