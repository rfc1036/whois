#ifndef SIMPLE_RECODE_H
#define SIMPLE_RECODE_H

#include <iconv.h>
#include <stdio.h>

extern iconv_t simple_recode_iconv_handle;
extern const char *simple_recode_input_charset;

char *simple_recode(const iconv_t handle, const char *str);
int recode_fputs(const char *s, FILE* stream);
void simple_recode_iconv_close(void);

#endif
