/* mkpasswd.c - written by Marco d'Itri <md@linux.it>, 1999/10/3.
 * Silly little program for encrypting passwords
 * It is so dumb that I will just place it in the public domain
 */

#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    if (argc != 3) {
	puts("Usage: mkpasswd PASSWORD SALT\n");
	exit(1);
    }
    printf("%s", crypt(argv[1], argv[2]));
    exit(0);
}

