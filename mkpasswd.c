/*
 * Copyright (C) 2001-2008  Marco d'Itri
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* for crypt, snprintf and strcasecmp */
#define _XOPEN_SOURCE
#define _BSD_SOURCE

/* System library */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "config.h"
#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#endif
#include <string.h>
#include <time.h>
#include <sys/types.h>
#ifdef HAVE_XCRYPT
#include <xcrypt.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

/* Application-specific */
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
#endif

static const char valid_salts[] = "abcdefghijklmnopqrstuvwxyz"
"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

struct crypt_method {
    const char *method;		/* short name used by the command line option */
    const char *prefix;		/* salt prefix */
    const unsigned int len;	/* salt lenght */
    const unsigned int rounds;	/* supports a variable number of rounds */
    const char *desc;		/* long description for the methods list */
};

static const struct crypt_method methods[] = {
    /* method		prefix	len rounds description */
    { "des",		"",	2,  0,
	N_("standard 56 bit DES-based crypt(3)") },
    { "md5",		"$1$",	8,  0, "MD5" },
#if defined FreeBSD
    { "bf",		"$2$",  22, 0, "Blowfish (FreeBSD)" },
#endif
#if defined OpenBSD || defined HAVE_XCRYPT
    { "bf",		"$2a$", 22, 1, "Blowfish" },
#endif
#if defined FreeBSD
    { "nt",		"$3$",   0, 0, "NT-Hash" },
#endif
#if defined HAVE_SHA_CRYPT
    /* http://people.redhat.com/drepper/SHA-crypt.txt */
    { "sha-256",	"$5$",	16, 1, "SHA-256" },
    { "sha-512",	"$6$",	16, 1, "SHA-512" },
#endif
    /* http://www.crypticide.com/dropsafe/article/1389 */
/* proper support is hard since solaris >= 9 supports pluggable methods
#if defined __SVR4 && defined __sun
    { "sunmd5",		"$md5$", ?, 1, "SunMD5" },
*/
#if defined HAVE_XCRYPT
    { "sha",		"{SHA}", 0, 0, "SHA-1" },
#endif
    { NULL,		NULL,	 0, 0, NULL }
};

void generate_salt(char *const buf, const unsigned int len);
void *gather_entropy(const int len);
void display_help(void);
void display_version(void);
void display_methods(void);

int main(int argc, char *argv[])
{
    int ch, i;
    int password_fd = -1;
    unsigned int salt_len = 0;
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

    while ((ch = GETOPT_LONGISH(argc, argv, "hH:m:P:R:sSV", longopts, 0)) > 0) {
	switch (ch) {
	case 'm':
	case 'H':
	    if (!optarg || strcaseeq("help", optarg)) {
		display_methods();
		exit(0);
	    }
	    for (i = 0; methods[i].method != NULL; i++)
		if (strcaseeq(methods[i].method, optarg)) {
		    salt_prefix = methods[i].prefix;
		    salt_len = methods[i].len;
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
		rounds = strtol(optarg, &p, 10);
		if (p == NULL || *p != '\0' || rounds < 0) {
		    fprintf(stderr, _("Invalid number '%s'.\n"), optarg);
		    exit(1);
		}
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
	    display_help();
	    exit(0);
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
	display_help();
	exit(1);
    }

    /* default: DES password */
    if (!salt_prefix) {
	salt_len = methods[0].len;
	salt_prefix = methods[0].prefix;
    }

    if (streq(salt_prefix, "$2a$")) {		/* OpenBSD Blowfish  */
	if (rounds <= 4)
	    rounds = 4;
	/* actually for 2a it is the logarithm of the number of rounds */
	snprintf(rounds_str, sizeof(rounds_str), "%02u$", rounds);
    } else if (rounds_support && rounds)
	snprintf(rounds_str, sizeof(rounds_str), "rounds=%u$", rounds);
    else
	rounds_str[0] = '\0';

    if (salt_arg) {
	unsigned int c = strlen(salt_arg);
	/* XXX: should support methods which support variable-length salts */
	if (c != salt_len) {
	    fprintf(stderr,
		    _("Wrong salt length: %d byte(s) when %d expected.\n"),
		    c, salt_len);
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
#ifdef HAVE_XCRYPT
	void *entropy = gather_entropy(64);

	salt = crypt_gensalt(salt_prefix, rounds, entropy, 64);
	if (!salt) {
		fprintf(stderr, "crypt_gensalt failed.\n");
		exit(2);
	}
	free(entropy);
#else
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
	unsigned char *p;

	if (isatty(password_fd))
	    fprintf(stderr, _("Password: "));
	password = NOFAIL(malloc(128));
	fp = fdopen(password_fd, "r");
	if (!fp) {
	    perror("fdopen");
	    exit(2);
	}
	if (!fgets(password, 128, fp)) {
	    perror("fgets");
	    exit(2);
	}

	p = (unsigned char *)password;
	while (*p) {
	    if (*p == '\n' || *p == '\r') {
		*p = '\0';
		break;
	    }
	    /* which characters are valid? */
	    if (*p > 0x7f) {
		fprintf(stderr,
			_("Illegal password character '0x%hhx'.\n"), *p);
		exit(1);
	    }
	    p++;
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
	    fprintf(stderr, "crypt failed.\n");
	    exit(2);
	}
	if (!strneq(result, salt_prefix, strlen(salt_prefix))) {
	    fprintf(stderr, _("Method not supported by crypt(3).\n"));
	    exit(2);
	}
	printf("%s\n", result);
    }

    exit(0);
}

#ifdef HAVE_XCRYPT

#ifndef RANDOM_DEVICE
#define RANDOM_DEVICE "/dev/urandom"
#endif

void* gather_entropy(const int count)
{
    char *buf;
    int fd;

    buf = NOFAIL(malloc(count));
    fd = open(RANDOM_DEVICE, O_RDONLY);
    if (fd < 0) {
	perror("open");
	exit(2);
    }
    if (read(fd, buf, count) != count) {
	perror("open");
	exit(2);
    }
    close(fd);

    return buf;
}

#else

void generate_salt(char *const buf, const unsigned int len)
{
    unsigned int i;

    srand(time(NULL) + getpid());
    for (i = 0; i < len; i++)
	buf[i] = valid_salts[rand() % (sizeof valid_salts - 1)];
    buf[i] = '\0';
}

#endif

void display_help(void)
{
    fprintf(stderr, _("Usage: mkpasswd [OPTIONS]... [PASSWORD [SALT]]\n"
	    "Crypts the PASSWORD using crypt(3).\n\n"));
    fprintf(stderr, _(
"      -m, --method=TYPE     select method TYPE\n"
"      -S, --salt=SALT       use the specified SALT\n"
"      -R, --rounds=NUMBER   use the specified NUMBER of rounds\n"
"      -P, --password-fd=NUM read the password from file descriptor NUM\n"
"                            instead of /dev/tty\n"
"      -s, --stdin           like --password-fd=0\n"
"      -h, --help            display this help and exit\n"
"      -V, --version         output version information and exit\n"
"\n"
"If PASSWORD is missing then it is asked interactively.\n"
"If no SALT is specified, a random one is generated.\n"
"If TYPE is 'help', available methods are printed.\n"
"\n"
"Report bugs to %s.\n"), "<md+whois@linux.it>");
}

void display_version(void)
{
    printf("mkpasswd %s\n\n", VERSION);
    puts("Copyright (C) 2001-2008 Marco d'Itri\n"
"This is free software; see the source for copying conditions.  There is NO\n"
"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.");
}

void display_methods(void)
{
    int i;

    printf(_("Available methods:\n"));
    for (i = 0; methods[i].method != NULL; i++)
	printf("%s\t%s\n", methods[i].method, methods[i].desc);
}

