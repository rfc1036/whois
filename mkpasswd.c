/*
 *    Copyright (C) 2001-2002  Marco d'Itri
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define _XOPEN_SOURCE
#define _BSD_SOURCE
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

#ifdef HAVE_GETOPT_LONG
static struct option longopts[] = {
    {"hash",		optional_argument,	NULL, 'H'},
    {"help",		no_argument,		NULL, 'h'},
    {"password-fd",	required_argument,	NULL, 'P'},
    {"stdin",		no_argument,		NULL, 's'},
    {"salt",		required_argument,	NULL, 'S'},
    {"version",		no_argument,		NULL, 'V'},
    {NULL,		0,			NULL, 0  }
};
#endif

static char valid_salts[] = "abcdefghijklmnopqrstuvwxyz"
"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

struct salt_prefix {
    const char *algo;	/* short name used by the command line option */
    const char *prefix;	/* salt prefix */
    unsigned int len;	/* salt lenght */
    const char *desc;	/* long description for the algorithms list */
};

struct salt_prefix salt_prefixes[] = {
    { "des",		"",	2, N_("\tstandard 56 bit DES-based crypt(3)") },
    { "md5",		"$1$",	8, "\tMD5" },
/* untested! is the salt correctly generated? */
#if defined OpenBSD || defined FreeBSD
    { "blf",		"$2$", 16, "\tBlowfish" },
#endif
/* untested too, and does not even compile */
#if defined HAVE_XCRYPT
    { "blf",		"$2a$", 16, "\tBlowfish" },
    { "sha",		"{SHA}", , "\tSHA-1" },
#endif
    { NULL,		NULL,	0, NULL }
};

void generate_salt(char *buf, const unsigned int len);
void display_help(void);
void display_version(void);
void display_algorithms(void);

int main(int argc, char *argv[])
{
    int ch;
    int password_fd = -1;
    unsigned int i, salt_len = 0;
    const char *salt_prefix = NULL;
    char *salt = NULL;
    char *password = NULL;

#ifdef ENABLE_NLS
    setlocale(LC_ALL, "");
    bindtextdomain(NLS_CAT_NAME, LOCALEDIR);
    textdomain(NLS_CAT_NAME);
#endif

    while ((ch = GETOPT_LONGISH(argc, argv, "hH:P:sS:V", longopts, 0)) > 0) {
	switch (ch) {
	case 'H':
	    if (!optarg || strcasecmp("help", optarg) == 0) {
		display_algorithms();
		exit(0);
	    }
	    for (i = 0; salt_prefixes[i].algo != NULL; i++)
		if (strcasecmp(salt_prefixes[i].algo, optarg) == 0) {
		    salt_prefix = salt_prefixes[i].prefix;
		    salt_len = salt_prefixes[i].len;
		    break;
		}
	    if (!salt_prefix) {
		fprintf(stderr, _("Invalid hash type '%s'.\n"), optarg);
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
	case 's':
	    password_fd = 0;
	    break;
	case 'S':
	    salt = optarg;
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

    if (argc == 2 && !salt) {
	password = argv[0];
	salt = argv[1];
    } else if (argc == 1) {
	password = argv[0];
    } else if (argc == 0) {
    } else {
	display_help();
	exit(1);
    }

    /* default: DES password */
    if (!salt_len) {
	salt_len = salt_prefixes[0].len;
	salt_prefix = salt_prefixes[0].prefix;
    }

    if (salt) {
	unsigned int c = strlen(salt);
	if (c != salt_len) {
	    fprintf(stderr,
		    _("Wrong salt length: %d byte(s) when %d expected.\n"),
		    c, salt_len);
	    exit(1);
	}
	while (c-- > 0)
	    if (strchr(valid_salts, salt[c]) == NULL) {
		fprintf(stderr, _("Illegal salt character '%c'.\n"), salt[c]);
		exit(1);
	    }
    } else {
#ifdef HAVE_XCRYPT
	char *entropy = gather_entropy(4096);
	salt = crypt_gensalt(salt_prefix, 0, entropy, 4096);
	if (!salt) {
		perror("crypt");
		exit(2);
	}
	free(entropy);
#else
	salt = malloc(salt_len + 1);
	generate_salt(salt, salt_len);
#endif
    }

    if (!password) {
	if (password_fd != -1) {
	    FILE *fp;
	    unsigned char *p;

	    if (isatty(password_fd))
		fprintf(stderr, _("Password: "));
	    password = malloc(128);
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
		if (*p == '\n') {
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
    }

    {
	char *pw, *result;
	pw = malloc(strlen(salt_prefix) + strlen(salt) + 1);
	*pw = '\0';
	strcat(pw, salt_prefix);
	strcat(pw, salt);
	result = crypt(password, pw);
	if (!result) {
		perror("crypt");
		exit(2);
	}
	printf("%s\n", result);
    }
    exit(0);
}

#ifndef HAVE_XCRYPT
void generate_salt(char *buf, const unsigned int len)
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
"      -H, --hash=TYPE       select hash TYPE\n"
"      -S, --salt=SALT       use the specified SALT\n"
"      -P, --password-fd=NUM read the password from file descriptor NUM\n"
"                            instead of /dev/tty\n"
"      -s, --stdin           like --password-fd=0\n"
"      -h, --help            display this help and exit\n"
"      -V, --version         output version information and exit\n"
"\n"
"If PASSWORD is missing then it is asked interactively.\n"
"If no SALT is specified, a random one is generated.\n"
"If TYPE is 'help', available algorithms are printed.\n"
"\n"
"Report bugs to %s.\n"), "<md+whois@linux.it>");
}

void display_version(void)
{
    printf("GNU mkpasswd %s\n\n", VERSION);
    puts("Copyright (C) 2001-2004 Marco d'Itri\n"
"This is free software; see the source for copying conditions.  There is NO\n"
"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.");
}

void display_algorithms(void)
{
    int i;

    printf(_("Available algorithms:\n"));
    for (i = 0; salt_prefixes[i].algo != NULL; i++)
	printf("%s%s\n", salt_prefixes[i].algo, salt_prefixes[i].desc);
}
