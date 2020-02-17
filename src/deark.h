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

#define DE_VERSION_NUMBER 0x01050400U
#define DE_VERSION_SUFFIX ""
#define DE_COPYRIGHT_YEAR_STRING "2020"

#ifdef DE_WINDOWS

#define i64 __int64
#define u64 unsigned __int64
#define i32 int
#define u32 unsigned int
#define i16 short
#define u16 unsigned short
#define u8 unsigned char
#define I64_FMT "I64d"
#define U64_FMT "I64u"
#define U64_FMTx "I64x"
#define U64_FMTo "I64o"

#else

#define i64 int64_t
#define u64 uint64_t
#define i32 int32_t
#define u32 uint32_t
#define i16 int16_t
#define u16 uint16_t
#define u8 unsigned char
#define I64_FMT PRId64
#define U64_FMT PRIu64
#define U64_FMTx PRIx64
#define U64_FMTo PRIo64

#endif

// "uint" is short for "unsigned int". It will not be redefined.
#define uint unsigned int

#define DE_CHAR_TIMES "\xc3\x97"
#define DE_CHAR_RIGHTARROW "\xe2\x86\x92"
#define DE_CHAR_LEQ "\xe2\x89\xa4"
#define DE_CHAR_GEQ "\xe2\x89\xa5"

struct deark_struct;
typedef struct deark_struct deark;

char *de_get_version_string(char *buf, size_t bufsize);
unsigned int de_get_version_int(void);
void de_exitprocess(int s);

void *de_malloc(deark *c, i64 n);
void *de_mallocarray(deark *c, i64 nmemb, size_t membsize);
void *de_realloc(deark *c, void *m, i64 oldsize, i64 newsize);
void *de_reallocarray(deark *c, void *m, i64 oldnmemb, size_t membsize,
	i64 newnmemb);
void de_free(deark *c, void *m);
char *de_strdup(deark *c, const char *s);
int de_atoi(const char *string);
i64 de_strtoll(const char *string, char **endptr, int base);
i64 de_atoi64(const char *string);
int de_strcasecmp(const char *a, const char *b);
int de_strncasecmp(const char *a, const char *b, size_t n);
void de_vsnprintf(char *buf, size_t buflen, const char *fmt, va_list ap);
void de_snprintf(char *buf, size_t buflen, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 3, 4)));

// Used by de_set_extract_policy()
#define DE_EXTRACTPOLICY_DEFAULT  0
#define DE_EXTRACTPOLICY_MAINONLY 1
#define DE_EXTRACTPOLICY_AUXONLY  2

#define DE_OVERWRITEMODE_DEFAULT  0
#define DE_OVERWRITEMODE_NEVER    1
#define DE_OVERWRITEMODE_STANDARD 2

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
	u32 param1);

typedef void (*de_fatalerrorfn_type)(deark *c);

// Used by de_set_output_style()
#define DE_OUTPUTSTYLE_DIRECT 0
#define DE_OUTPUTSTYLE_ARCHIVE 1
#define DE_OUTPUTSTYLE_STDOUT 2
#define DE_ARCHIVEFMT_ZIP     1
#define DE_ARCHIVEFMT_TAR     2

void de_puts(deark *c, unsigned int flags, const char *s);
void de_printf(deark *c, unsigned int flags, const char *fmt, ...)
	de_gnuc_attribute ((format (printf, 3, 4)));

void de_utf8_to_ascii(const char *src, char *dst, size_t dstlen, unsigned int flags);
