/*
 * Copyright 2009 by Marco d'Itri <md@linux.it>.
 *
 * simple_recode was inspired by a similar function found in Simon
 * Josefsson's libidn.
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

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <iconv.h>
#ifndef WIN32
#include <langinfo.h>
#endif

#include "utils.h"

#include "simple_recode.h"

/* Global variables */
iconv_t simple_recode_iconv_handle;
const char *simple_recode_input_charset;

#ifdef WIN32
extern char* win32_charset;
#endif

/*
 * These value should be tuned to an acceptable compromise between memory
 * usage and calling iconv(3) as few times as possible.
 */
#define SIMPLE_RECODE_BUFFER_SIZE_1 256
#define SIMPLE_RECODE_BUFFER_SIZE_2 1024
#define SIMPLE_RECODE_BUFFER_INCREMENT 1

/*
 * Convert a NULL-terminated string accordingly to the provided iconv(3)
 * handle. The returned string is allocated using malloc(3) and needs to be
 * deallocated by the caller.
 * Incomplete, invalid and impossible to recode sequences are copied as-is.
 * On failure, NULL is returned and errno is set.
 */
char *simple_recode(const iconv_t handle, const char *str)
{
    char *inp = (char *) str;
    char *outp, *result;
    size_t inbytes_remaining, outbytes_remaining, outbuf_size;

    inbytes_remaining = strlen(inp);
    if (inbytes_remaining + 1 <= SIMPLE_RECODE_BUFFER_SIZE_1
	    - (SIMPLE_RECODE_BUFFER_SIZE_1 >> SIMPLE_RECODE_BUFFER_INCREMENT))
	outbuf_size = SIMPLE_RECODE_BUFFER_SIZE_1;
    else
	outbuf_size = inbytes_remaining + 1
	    + (inbytes_remaining >> SIMPLE_RECODE_BUFFER_INCREMENT);

    outp = result = malloc(outbuf_size);
    if (!result)
	return NULL;
    outbytes_remaining = outbuf_size - 1;

    do {
	size_t err = iconv(handle, &inp, &inbytes_remaining, &outp,
		&outbytes_remaining);

	if (err != -1)
	    break; /* success */

	switch (errno) {
	case EINVAL:		/* incomplete multibyte sequence */
	case EILSEQ:		/* invalid multibyte sequence */
#ifdef SIMPLE_RECODE_SKIP_INVALID_SEQUENCES
	    /* recover from invalid input by replacing it with a '?' */
	    inp++;
	    *outp++ = '?';	/* use U+FFFD for unicode output? how? */
#else
	    /* garbage in, garbage out */
	    *outp++ = *inp++;
#endif
	    inbytes_remaining--;
	    outbytes_remaining--;
	    continue;

	case E2BIG:
	    {
		size_t used = outp - result;
		size_t newsize;
		char *new_result;

		if (outbuf_size < SIMPLE_RECODE_BUFFER_SIZE_2)
		    newsize = SIMPLE_RECODE_BUFFER_SIZE_2;
		else
		    newsize = outbuf_size
			+ (outbuf_size >> SIMPLE_RECODE_BUFFER_INCREMENT);

		/* check if the newsize variable has overflowed */
		if (newsize <= outbuf_size) {
		    free(result);
		    errno = ENOMEM;
		    return NULL;
		}
		outbuf_size = newsize;
		new_result = realloc(result, outbuf_size);
		if (!new_result) {
		    free(result);
		    return NULL;
		}
		result = new_result;

		/* update the position in the new output stream */
		outp = result + used;
		outbytes_remaining = outbuf_size - used - 1;

		continue;
	    }

	default:
	    free(result);
	    return NULL;
	}
    } while (inbytes_remaining > 0);

    *outp = '\0';

    return result;
}

/*
 * Like fputs(3), but transparently recodes s using the global variable
 * simple_recode_input_charset as the input charset and the current locale
 * as the output charset.
 * If simple_recode_input_charset is NULL it just calls fputs(3).
 * Exits with an error if iconv(3) or iconv_open(3) fail.
 *
 * Assumes that setlocale(3) has already been called.
 *
 * If appropriate, the iconv object referenced by the global variable
 * simple_recode_iconv_handle should be deallocated with iconv_close(3).
 */
int recode_fputs(const char *s, FILE *stream)
{
    char *out;
    int result;

    if (simple_recode_input_charset == NULL)	/* no conversion is needed */
	return fputs(s, stream);

    if (simple_recode_iconv_handle == NULL) {
#ifdef WIN32
        simple_recode_iconv_handle = iconv_open(win32_charset,
					 simple_recode_input_charset);
#else
	simple_recode_iconv_handle = iconv_open(nl_langinfo(CODESET),
					 simple_recode_input_charset);
#endif
	if (simple_recode_iconv_handle == (iconv_t) - 1)
	    err_sys("iconv_open");
    }

    out = simple_recode(simple_recode_iconv_handle, s);
    if (!out)
	err_sys("iconv");
    result = fputs(out, stream);
    free(out);

    return result;
}

void simple_recode_iconv_close(void)
{
    if (simple_recode_iconv_handle == NULL)
	return;

    iconv_close(simple_recode_iconv_handle);
    simple_recode_iconv_handle = NULL;
    simple_recode_input_charset = NULL;
}

