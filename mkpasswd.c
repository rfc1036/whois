/*
 *    Copyright (C) 2001  Marco d'Itri
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
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "config.h"
#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#endif

#ifdef HAVE_GETOPT_LONG
static struct option longopts[] = {
    {"stdin",		no_argument,		NULL, 's'},
    {"salt",		required_argument,	NULL, 'S'},
    {"hash",		required_argument,	NULL, 'H'},
    {"help",		no_argument,		NULL, 'h'},
    {"version",		no_argument,		NULL, 'V'},
    {NULL,		0,			NULL, 0  }
};
#endif

static char valid_salts[] = "abcdefghijklmnopqrstuvwxyz"
"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

struct salt_prefix {
    const char *algo;
    const char *prefix;
    unsigned int len;
};

struct salt_prefix salt_prefixes[] = {
    { "des",	"",	2 },
    { "md5",	"$1$",	8 },
};

void generate_salt(char *buf, const unsigned int len);
void display_help(void);
void display_version(void);
void display_algorithms(void);

int main(int argc, char *argv[])
{
    int ch;
    int use_stdin = 0;
    unsigned int i, salt_len = 0;
    const char *salt_prefix = NULL;
    char *salt = NULL;
    char *password = NULL;
    unsigned char *p;

    while ((ch = GETOPT_LONGISH(argc, argv, "hH:sS:V", longopts, 0)) > 0) {
	switch (ch) {
	case 's':
	    use_stdin = 1;
	    break;
	case 'S':
	    salt = optarg;
	    break;
	case 'H':
	    if (*optarg == '\0') {
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
		fprintf(stderr, "Invalid hash type `%s'.\n", optarg);
		exit(1);
	    }
	    break;
	case 'V':
	    display_version();
	    exit(0);
	case 'h':
	    display_help();
	    exit(0);
	default:
	    fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);
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
	i = strlen(salt);
	if (i != salt_len) {
	    fprintf(stderr, "Wrong salt length: %d byte(s) instead of %d.\n",
		    i, salt_len);
	    exit(1);
	}
	while (i-- > 0)
	    if (strchr(valid_salts, salt[i]) == NULL) {
		fprintf(stderr, "Illegal salt character `%c'.\n", salt[i]);
		exit(1);
	    }
    } else {
	salt = malloc(salt_len + 1);
	generate_salt(salt, salt_len);
    }

    if (!password) {
	if (use_stdin) {
	    fprintf(stderr, "Password: ");
	    password = malloc(128);
	    if (!fgets(password, sizeof password, stdin)) {
		perror("fgets:");
		exit(2);
	    }
	    p = password;
	    while (*p != '\0') {
		if (*p == '\n') {
		    *p = '\0';
		    break;
		}
		/* which characters are valid? */
		if (*p > 0x7f) {
		    fprintf(stderr, "Illegal password character `0x%hhx'.\n",
			    *p);
		    exit(1);
		}
		p++;
	    }
	} else {
	    password = getpass("Password: ");
	    if (!password) {
		perror("getpass:");
		exit(2);
	    }
	}
    }

    p = malloc(strlen(salt_prefix) + strlen(salt) + 1);
    *p = '\0';
    strcat(p, salt_prefix);
    strcat(p, salt);
    printf("%s\n", crypt(password, p));
    exit(0);
}

void generate_salt(char *buf, const unsigned int len)
{
    unsigned int i;

    srand(time(NULL) + getpid());
    for (i = 0; i < len; i++)
	buf[i] = valid_salts[rand() % (sizeof valid_salts - 1)];
    buf[i] = '\0';
}

void display_help(void)
{
    fprintf(stderr, "Usage: mkpasswd [OPTIONS]... [PASSWORD [SALT]]\n"
	    "Crypts the PASSWORD using crypt(3).\n\n");
    fprintf(stderr,
"      -H, --hash=TYPE       select hash TYPE\n"
"      -S, --salt=SALT       use the specified SALT\n"
"      -s, --stdin           read the password from stdin instead of /dev/tty\n"
"      -h, --help            display this help and exit\n"
"      -v, --version         output version information and exit\n"
"\n"
"If PASSWORD is missing then it is asked interactively.\n"
"If no SALT is specified, a random one is generated.\n"
"\n"
"Report bugs to %s.\n", "<md+whois@linux.it>");
}

void display_version(void)
{
    printf("GNU mkpasswd %s\n\n", VERSION);
    puts("Copyright (C) 2001 Marco d'Itri\n"
"This is free software; see the source for copying conditions.  There is NO\n"
"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.");
}

void display_algorithms(void)
{
    printf("Available algorithms:\n");
}
