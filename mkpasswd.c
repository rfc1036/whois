/*
 * Copyright (C) 2001-2019 Marco d'Itri <md@linux.it>.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* for crypt, snprintf and strcasecmp */
#define _XOPEN_SOURCE 500
#define _BSD_SOURCE 1
#define _DEFAULT_SOURCE 1
#define __EXTENSIONS__ 1

/* System library */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "config.h"
#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#endif
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/types.h>
#ifdef HAVE_XCRYPT_H
#include <xcrypt.h>
#include <sys/stat.h>
#endif
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
#ifdef HAVE_GETTIMEOFDAY
#include <sys/time.h>
#endif

/* Application-specific */
#include "version.h"
#include "utils.h"

/* Global variables */
#ifdef HAVE_GETOPT_LONG
static const struct option longopts[] = {
    {"method",		optional_argument,	NULL, 'm'},
    /* for backward compatibility with versions < 4.7.25 (< 20080321): */
    {"hash",		optional_argument,	NULL, 'H'},
    {"help",		no_argument,		NULL, 'h'},
    {"password-fd",	required_argument,	NULL, 'P'},
    {"stdin",		no_argument,		NULL, 's'},
    {"salt",		required_argument,	NULL, 'S'},
    {"rounds",		required_argument,	NULL, 'R'},
    {"version",		no_argument,		NULL, 'V'},
    {NULL,		0,			NULL, 0  }
};
#else
extern char *optarg;
extern int optind;
#endif

static const char valid_salts[] = "abcdefghijklmnopqrstuvwxyz"
"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

struct crypt_method {
    const char *method;		/* short name used by the command line option */
    const char *prefix;		/* salt prefix */
    const unsigned int minlen;	/* minimum salt length */
    const unsigned int maxlen;	/* maximum salt length */
    const unsigned int rounds;	/* supports a variable number of rounds */
    const char *desc;		/* long description for the methods list */
};

/* XCRYPT_VERSION_NUM is defined in crypt.h from libxcrypt */
#if defined XCRYPT_VERSION_NUM
# define HAVE_SHA_CRYPT
# define HAVE_BCRYPT
# define HAVE_BSDICRYPT
#endif

static const struct crypt_method methods[] = {
    /* method		prefix	minlen,	maxlen	rounds description */
#ifdef CRYPT_GENSALT_IMPLEMENTS_DEFAULT_PREFIX
    { "auto",		NULL,	0,	0,	0, NULL },
#endif
    /* compatibility aliases for mkpasswd versions < 5.4.0 */
    { "des",		"",	2,	2,	0, NULL },
    { "md5",		"$1$",	8,	8,	0, NULL },
#if defined XCRYPT_VERSION_NUM
    { "yescrypt",	"$y$",	0,	0,	0, "Yescrypt" },
#if XCRYPT_VERSION_NUM >= ((4 << 16) | 4)
    { "gost-yescrypt",	"$gy$",	0,	0,	0, "GOST Yescrypt" },
#endif
    { "scrypt",		"$7$",	0,	0,	0, "scrypt" },
#endif
#ifdef HAVE_BCRYPT_OBSOLETE
    /* http://marc.info/?l=openbsd-misc&m=139320023202696 */
    { "bf",		"$2a$", 22,	22,	2, "bcrypt" },
#endif
#ifdef HAVE_BCRYPT
    { "bcrypt",		"$2b$", 22,	22,	2, "bcrypt" },
    { "bcrypt-a",	"$2a$", 22,	22,	2, "bcrypt (obsolete $2a$ version)" },
#endif
#if defined HAVE_SHA_CRYPT
    /* http://people.redhat.com/drepper/SHA-crypt.txt */
    { "sha512crypt",	"$6$",	8,	16,	1, "SHA-512" },
    { "sha256crypt",	"$5$",	8,	16,	1, "SHA-256" },
    /* compatibility aliases for mkpasswd versions < 5.4.0 */
    { "sha-256",	"$5$",	8,	16,	1, NULL },
    { "sha-512",	"$6$",	8,	16,	1, NULL },
#endif
#if (defined __SVR4 && defined __sun) || defined XCRYPT_VERSION_NUM
    /* http://www.crypticide.com/dropsafe/article/1389 */
    /*
     * Actually the maximum salt length is arbitrary, but Solaris by default
     * always uses 8 characters:
     * http://cvs.opensolaris.org/source/xref/onnv/onnv-gate/ \
     *   usr/src/lib/crypt_modules/sunmd5/sunmd5.c#crypt_gensalt_impl
     */
    { "sunmd5",		"$md5$", 8,	8,	1, "SunMD5" },
#endif
    { "md5crypt",	"$1$",	8,	8,	0, "MD5" },
#ifdef HAVE_BSDICRYPT
    { "bsdicrypt",		"_",	0,	0,	0,
	N_("BSDI extended DES-based crypt(3)") },
#endif
    { "descrypt",	"",	2,	2,	0,
	N_("standard 56 bit DES-based crypt(3)") },
#if defined FreeBSD || defined XCRYPT_VERSION_NUM
    { "nt",		"$3$",  0,	0,	0, "NT-Hash" },
#endif
    { NULL,		NULL,	0,	0,	0, NULL }
};

void generate_salt(char *const buf, const unsigned int len);
void *get_random_bytes(const unsigned int len);
void NORETURN display_help(int error);
void display_version(void);
void display_methods(void);
char *read_line(FILE *fp);

int main(int argc, char *argv[])
{
    int ch, i;
    int password_fd = -1;
    unsigned int salt_minlen = 0;
    unsigned int salt_maxlen = 0;
    unsigned int rounds_support = 0;
    const char *salt_prefix = NULL;
    const char *salt_arg = NULL;
    unsigned int rounds = 0;
    char *salt = NULL;
    char rounds_str[30];
    char *password = NULL;

#ifdef ENABLE_NLS
    setlocale(LC_ALL, "");
    bindtextdomain(NLS_CAT_NAME, LOCALEDIR);
    textdomain(NLS_CAT_NAME);
#endif

    /* prepend options from environment */
    argv = merge_args(getenv("MKPASSWD_OPTIONS"), argv, &argc);

    while ((ch = GETOPT_LONGISH(argc, argv, "hH:m:5P:R:sS:V", longopts, NULL))
	    > 0) {
	switch (ch) {
	case '5':
	    optarg = (char *) "md5";
	    /* fall through */
	case 'm':
	case 'H':
	    if (!optarg || strcaseeq("help", optarg)) {
		display_methods();
		exit(0);
	    }
#if defined HAVE_LINUX_CRYPT_GENSALT || defined HAVE_SOLARIS_CRYPT_GENSALT
	    if (optarg[0] == '$'
		    && strlen(optarg) > 2
		    && *(optarg + strlen(optarg) - 1) == '$') {
		salt_prefix = NOFAIL(strdup(optarg));
		salt_minlen = 0;
		salt_maxlen = 0;
		rounds_support = 0;
		break;
	    }
#endif
	    for (i = 0; methods[i].method != NULL; i++)
		if (strcaseeq(methods[i].method, optarg)) {
		    salt_prefix = methods[i].prefix;
		    salt_minlen = methods[i].minlen;
		    salt_maxlen = methods[i].maxlen;
		    rounds_support = methods[i].rounds;
		    break;
		}
	    if (!salt_prefix) {
		fprintf(stderr, _("Invalid method '%s'.\n"), optarg);
		exit(1);
	    }
	    break;
	case 'P':
	    {
		char *p;
		password_fd = strtol(optarg, &p, 10);
		if (p == NULL || *p != '\0' || password_fd < 0) {
		    fprintf(stderr, _("Invalid number '%s'.\n"), optarg);
		    exit(1);
		}
	    }
	    break;
	case 'R':
	    {
		char *p;
		long r;

		r = strtol(optarg, &p, 10);
		if (p == NULL || *p != '\0' || r < 0) {
		    fprintf(stderr, _("Invalid number '%s'.\n"), optarg);
		    exit(1);
		}
		rounds = r;
	    }
	    break;
	case 's':
	    password_fd = 0;
	    break;
	case 'S':
	    salt_arg = optarg;
	    break;
	case 'V':
	    display_version();
	    exit(0);
	case 'h':
	    display_help(EXIT_SUCCESS);
	default:
	    fprintf(stderr, _("Try '%s --help' for more information.\n"),
		    argv[0]);
	    exit(1);
	}
    }
    argc -= optind;
    argv += optind;

    if (argc == 2 && !salt_arg) {
	password = argv[0];
	salt_arg = argv[1];
    } else if (argc == 1) {
	password = argv[0];
    } else if (argc == 0) {
    } else {
	display_help(EXIT_FAILURE);
    }

    /* default: DES password, or else whatever crypt_gensalt chooses */
    if (!salt_prefix) {
	salt_minlen = methods[0].minlen;
	salt_maxlen = methods[0].maxlen;
	salt_prefix = methods[0].prefix;
	rounds_support = methods[0].rounds;
    }

    if (!salt_prefix) {
	/* NULL means that crypt_gensalt will choose one later */
    } else if (rounds_support == 2) {
	/* bcrypt strings always contain the rounds number */
	if (rounds <= 5)
	    rounds = 5;
	/* actually it is the logarithm of the number of rounds */
	snprintf(rounds_str, sizeof(rounds_str), "%02u$", rounds);
    } else if (rounds_support && rounds)
	snprintf(rounds_str, sizeof(rounds_str), "rounds=%u$", rounds);
    else
	rounds_str[0] = '\0';

    if (salt_arg) {
	unsigned int c = strlen(salt_arg);
	if (c < salt_minlen || c > salt_maxlen) {
	    if (salt_minlen == salt_maxlen)
		fprintf(stderr, ngettext(
			"Wrong salt length: %d byte when %d expected.\n",
			"Wrong salt length: %d bytes when %d expected.\n", c),
			c, salt_maxlen);
	    else
		fprintf(stderr, ngettext(
			"Wrong salt length: %d byte when %d <= n <= %d"
			" expected.\n",
			"Wrong salt length: %d bytes when %d <= n <= %d"
			" expected.\n", c),
			c, salt_minlen, salt_maxlen);
	    exit(1);
	}
	while (c-- > 0) {
	    if (strchr(valid_salts, salt_arg[c]) == NULL) {
		fprintf(stderr, _("Illegal salt character '%c'.\n"),
			salt_arg[c]);
		exit(1);
	    }
	}

	salt = NOFAIL(malloc(strlen(salt_prefix) + strlen(rounds_str)
		+ strlen(salt_arg) + 1));
	*salt = '\0';
	strcat(salt, salt_prefix);
	strcat(salt, rounds_str);
	strcat(salt, salt_arg);
    } else {
#ifdef HAVE_SOLARIS_CRYPT_GENSALT
	salt = crypt_gensalt(salt_prefix, NULL);
	if (!salt) {
	    perror("crypt_gensalt");
	    exit(2);
	}
#elif defined HAVE_LINUX_CRYPT_GENSALT
	void *entropy = get_random_bytes(64);

	salt = crypt_gensalt(salt_prefix, rounds, entropy, 64);
	if (!salt) {
	    perror("crypt_gensalt");
	    exit(2);
	}
	if (entropy)
	    free(entropy);
#else
	unsigned int salt_len = salt_maxlen;

	if (salt_minlen != salt_maxlen) { /* salt length can vary */
	    srand(time(NULL) + getpid());
	    salt_len = rand() % (salt_maxlen - salt_minlen + 1) + salt_minlen;
	}

	salt = NOFAIL(malloc(strlen(salt_prefix) + strlen(rounds_str)
		+ salt_len + 1));
	*salt = '\0';
	strcat(salt, salt_prefix);
	strcat(salt, rounds_str);
	generate_salt(salt + strlen(salt), salt_len);
#endif
    }

    if (password) {
    } else if (password_fd != -1) {
	FILE *fp;

	if (isatty(password_fd))
	    fprintf(stderr, _("Password: "));
	fp = fdopen(password_fd, "r");
	if (!fp) {
	    perror("fdopen");
	    exit(2);
	}

	password = read_line(fp);
	if (!password) {
	    perror("fgetc");
	    exit(2);
	}
    } else {
	password = getpass(_("Password: "));
	if (!password) {
	    perror("getpass");
	    exit(2);
	}
    }

    {
	const char *result;
	result = crypt(password, salt);
	/* xcrypt returns "*0" on errors */
	if (!result || result[0] == '*') {
	    if (CRYPT_SETS_ERRNO)
		perror("crypt");
	    else
		fprintf(stderr, "crypt failed.\n");
	    exit(2);
	}
	if (!strneq(result, salt, strlen(salt))) {
	    fprintf(stderr, _("Method not supported by crypt(3).\n"));
	    exit(2);
	}
	printf("%s\n", result);
    }

    exit(0);
}

#ifdef CRYPT_GENSALT_IMPLEMENTS_AUTO_ENTROPY

/*
 * If NULL is passed to the libxcrypt version of crypt_gensalt() instead of
 * the buffer of random bytes then the function will obtain by itself the
 * required randomness.
 */
inline void *get_random_bytes(const unsigned int count)
{
    return NULL;
}

#elif defined HAVE_SOLARIS_CRYPT_GENSALT

/*
 * The Solaris version of crypt_gensalt() gathers the random data by itself.
 */

#elif defined RANDOM_DEVICE || defined HAVE_ARC4RANDOM_BUF || defined HAVE_GETENTROPY

void *get_random_bytes(const unsigned int count)
{
    char *buf = NOFAIL(malloc(count));

#if defined HAVE_ARC4RANDOM_BUF
    arc4random_buf(buf, count);
#elif defined HAVE_GETENTROPY
    if (getentropy(buf, count) < 0)
	perror("getentropy");
#else
    int fd;
    ssize_t bytes_read;

    fd = open(RANDOM_DEVICE, O_RDONLY);
    if (fd < 0) {
	perror("open(" RANDOM_DEVICE ")");
	exit(2);
    }
    bytes_read = read(fd, buf, count);
    if (bytes_read < 0) {
	perror("read(" RANDOM_DEVICE ")");
	exit(2);
    }
    if (bytes_read != count) {
	fprintf(stderr, "Short read of %s.\n", RANDOM_DEVICE);
	exit(2);
    }
    close(fd);
#endif

    return buf;
}

void generate_salt(char *const buf, const unsigned int len)
{
    unsigned int i;
    unsigned char *entropy;

    entropy = get_random_bytes(len);

    for (i = 0; i < len; i++)
	buf[i] = valid_salts[entropy[i] % (sizeof valid_salts - 1)];
    buf[i] = '\0';
    free(entropy);
}

#else /* RANDOM_DEVICE || HAVE_ARC4RANDOM_BUF || HAVE_GETENTROPY */

void generate_salt(char *const buf, const unsigned int len)
{
    unsigned int i;

# ifdef HAVE_GETTIMEOFDAY
    struct timeval tv;

    gettimeofday(&tv, NULL);
    srand(tv.tv_sec ^ tv.tv_usec);

# else /* HAVE_GETTIMEOFDAY */
#  warning "This system lacks a strong enough random numbers generator!"

    /*
     * The possible values of time over one year are 31536000, which is
     * two orders of magnitude less than the allowed entropy range (2^32).
     */
    srand(time(NULL) + getpid());

# endif /* HAVE_GETTIMEOFDAY */

    for (i = 0; i < len; i++)
	buf[i] = valid_salts[rand() % (sizeof valid_salts - 1)];
    buf[i] = '\0';
}

#endif /* RANDOM_DEVICE || HAVE_ARC4RANDOM_BUF || HAVE_GETENTROPY*/

void NORETURN display_help(int error)
{
    fprintf((EXIT_SUCCESS == error) ? stdout : stderr,
	    _("Usage: mkpasswd [OPTIONS]... [PASSWORD [SALT]]\n"
	    "Crypts the PASSWORD using crypt(3).\n\n"));
    fprintf((EXIT_SUCCESS == error) ? stdout : stderr, _(
"      -m, --method=TYPE     select method TYPE\n"
"      -5                    like --method=md5\n"
"      -S, --salt=SALT       use the specified SALT\n"
    ));
    fprintf((EXIT_SUCCESS == error) ? stdout : stderr, _(
"      -R, --rounds=NUMBER   use the specified NUMBER of rounds\n"
"      -P, --password-fd=NUM read the password from file descriptor NUM\n"
"                            instead of /dev/tty\n"
"      -s, --stdin           like --password-fd=0\n"
    ));
    fprintf((EXIT_SUCCESS == error) ? stdout : stderr, _(
"      -h, --help            display this help and exit\n"
"      -V, --version         output version information and exit\n"
"\n"
"If PASSWORD is missing then it is asked interactively.\n"
"If no SALT is specified, a random one is generated.\n"
"If TYPE is 'help', available methods are printed.\n"
"\n"
"Report bugs to %s.\n"), "<md+whois@linux.it>");
    exit(error);
}

void display_version(void)
{
    printf("mkpasswd %s\n\n", VERSION);
    puts("Copyright (C) 2001-2019 Marco d'Itri\n"
"This is free software; see the source for copying conditions.  There is NO\n"
"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.");
}

void display_methods(void)
{
    unsigned int i;

    printf(_("Available methods:\n"));
    for (i = 0; methods[i].method != NULL; i++)
	if (methods[i].desc)
	    printf("%-15s %s\n", methods[i].method, methods[i].desc);
}

char *read_line(FILE *fp) {
    int size = 128;
    int ch;
    size_t pos = 0;
    char *password;

    password = NOFAIL(malloc(size));

    while ((ch = fgetc(fp)) != EOF) {
	if (ch == '\n' || ch == '\r')
	    break;
	password[pos++] = ch;
	if (pos == size) {
	    size += 128;
	    password = NOFAIL(realloc(password, size));
	}
    }
    password[pos] = '\0';

    if (ferror(fp)) {
	free(password);
	return NULL;
    }
    return password;
}

