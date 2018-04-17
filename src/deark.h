// This file is part of Deark.
// Copyright (C) 2016-2017 Jason Summers
// See the file COPYING for terms of use.

// Definitions visible to everything.

#ifdef DEARK_H_INC
#error "deark.h included multiple times"
#endif
#define DEARK_H_INC

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#ifndef DE_WINDOWS
#include <inttypes.h>
#endif

#ifdef __GNUC__
#define de_gnuc_attribute __attribute__
#else
#define de_gnuc_attribute(x)
#endif

#define DE_VERSION_NUMBER 0x01040600U
#define DE_VERSION_SUFFIX ""

#ifdef DE_WINDOWS

#define de_int64 __int64
#define de_uint64 unsigned __int64
#define de_int32 int
#define de_uint32 unsigned int
#define de_uint16 unsigned short
#define de_byte unsigned char
#define INT64_FMT "I64d"
#define INT64_FMTx "I64x"

#else

#define de_int64 int64_t
#define de_uint64 uint64_t
#define de_int32 int32_t
#define de_uint32 uint32_t
#define de_uint16 uint16_t
#define de_byte unsigned char
#define INT64_FMT PRId64
#define INT64_FMTx PRIx64

#endif

#define DE_CHAR_TIMES "\xc3\x97"
#define DE_CHAR_RIGHTARROW "\xe2\x86\x92"
#define DE_CHAR_LEQ "\xe2\x89\xa4"
#define DE_CHAR_GEQ "\xe2\x89\xa5"

struct deark_struct;
typedef struct deark_struct deark;

char *de_get_version_string(char *buf, size_t bufsize);
unsigned int de_get_version_int(void);

void *de_malloc(deark *c, de_int64 n);
void *de_realloc(deark *c, void *m, de_int64 oldsize, de_int64 newsize);
void de_free(deark *c, void *m);
char *de_strdup(deark *c, const char *s);
int de_atoi(const char *string);
de_int64 de_strtoll(const char *string, char **endptr, int base);
de_int64 de_atoi64(const char *string);
int de_strcasecmp(const char *a, const char *b);

// Used by de_set_extract_policy()
#define DE_EXTRACTPOLICY_DEFAULT  0
#define DE_EXTRACTPOLICY_MAINONLY 1
#define DE_EXTRACTPOLICY_AUXONLY  2

const char *de_get_ext_option(deark *c, const char *name);

#define DE_MSGTYPE_MESSAGE 0U
#define DE_MSGTYPE_WARNING 1U
#define DE_MSGTYPE_ERROR   2U
#define DE_MSGTYPE_DEBUG   3U
// The low bits of 'flags' are the message type.
typedef void (*de_msgfn_type)(deark *c, unsigned int flags, const char *s);

#define DE_MSGCODE_HL      0x1000U
#define DE_MSGCODE_UNHL    0x1100U
#define DE_MSGCODE_RGBSAMPLE 0x2000U
typedef void (*de_specialmsgfn_type)(deark *c, unsigned int flags, unsigned int code,
	de_uint32 param1);

typedef void (*de_fatalerrorfn_type)(deark *c);

// Used by de_set_output_style()
#define DE_OUTPUTSTYLE_DIRECT 0
#define DE_OUTPUTSTYLE_ZIP    1
#define DE_OUTPUTSTYLE_STDOUT 2

void de_puts(deark *c, unsigned int flags, const char *s);
void de_printf(deark *c, unsigned int flags, const char *fmt, ...)
	de_gnuc_attribute ((format (printf, 3, 4)));

void de_utf8_to_ascii(const char *src, char *dst, size_t dstlen, unsigned int flags);
