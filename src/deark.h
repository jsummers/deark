// This file is part of Deark.
// Copyright (C) 2016-2017 Jason Summers
// See the file COPYING for terms of use.

#ifdef DEARK_H_INC
#error "deark.h included multiple times"
#endif
#define DEARK_H_INC

#include <stdio.h>

#ifdef __GNUC__
#define de_gnuc_attribute __attribute__
#else
#define de_gnuc_attribute(x)
#endif

#define DE_VERSION_NUMBER 0x01040400U
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

#include <inttypes.h>
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

deark *de_create(void);
void de_destroy(deark *c);
void de_exitprocess(void);

void *de_malloc(deark *c, de_int64 n);
void *de_realloc(deark *c, void *m, de_int64 oldsize, de_int64 newsize);
void de_free(deark *c, void *m);
char *de_strdup(deark *c, const char *s);
int de_atoi(const char *string);
de_int64 de_strtoll(const char *string, char **endptr, int base);
de_int64 de_atoi64(const char *string);
int de_strcasecmp(const char *a, const char *b);

#define DE_INPUTSTYLE_FILE    0
#define DE_INPUTSTYLE_STDIN   1
void de_set_input_style(deark *c, int x);

void de_set_input_filename(deark *c, const char *fn);
void de_set_input_file_slice_start(deark *c, de_int64 n);
void de_set_input_file_slice_size(deark *c, de_int64 n);

void de_run(deark *c);

void de_print_module_list(deark *c);

void de_set_userdata(deark *c, void *x);
void *de_get_userdata(deark *c);

// 0=off  1=normal  2=verbose
void de_set_debug_level(deark *c, int x);
void de_set_dprefix(deark *c, const char *s);

#define DE_EXTRACTPOLICY_DEFAULT  0
#define DE_EXTRACTPOLICY_MAINONLY 1
#define DE_EXTRACTPOLICY_AUXONLY  2
void de_set_extract_policy(deark *c, int x);

// 1=normal. 2=extract everything we can, no matter how useless
void de_set_extract_level(deark *c, int x);

void de_set_listmode(deark *c, int x);
void de_set_want_modhelp(deark *c, int x);
void de_set_first_output_file(deark *c, int x);
void de_set_max_output_files(deark *c, int n);
void de_set_max_image_dimension(deark *c, de_int64 n);
void de_set_messages(deark *c, int x);
void de_set_warnings(deark *c, int x);

// When we write a UTF-8 text file, should we start it with a BOM?
void de_set_write_bom(deark *c, int x);

void de_set_write_density(deark *c, int x);

// Use only ASCII in HTML documents.
void de_set_ascii_html(deark *c, int x);

// If a file contains a name that we can use as part of the output filename,
// should we use it?
void de_set_filenames_from_file(deark *c, int x);

void de_set_preserve_file_times(deark *c, int x);

void de_set_ext_option(deark *c, const char *name, const char *val);
const char *de_get_ext_option(deark *c, const char *name);

#define DE_MSGTYPE_MESSAGE 0U
#define DE_MSGTYPE_WARNING 1U
#define DE_MSGTYPE_ERROR   2U
#define DE_MSGTYPE_DEBUG   3U
// The low bits of 'flags' are the message type.
typedef void (*de_msgfn_type)(deark *c, unsigned int flags, const char *s);
void de_set_messages_callback(deark *c, de_msgfn_type fn);

#define DE_MSGCODE_HL      0x1000U
#define DE_MSGCODE_UNHL    0x1100U
#define DE_MSGCODE_RGBSAMPLE 0x2000U
typedef void (*de_specialmsgfn_type)(deark *c, unsigned int flags, unsigned int code,
	de_uint32 param1);
void de_set_special_messages_callback(deark *c, de_specialmsgfn_type fn);

typedef void (*de_fatalerrorfn_type)(deark *c);
// The caller's fatalerror callback is not expected to return.
void de_set_fatalerror_callback(deark *c, de_fatalerrorfn_type fn);

void de_set_input_format(deark *c, const char *fmtname);

#define DE_OUTPUTSTYLE_DIRECT 0
#define DE_OUTPUTSTYLE_ZIP    1
#define DE_OUTPUTSTYLE_STDOUT 2
void de_set_output_style(deark *c, int x);

void de_puts(deark *c, unsigned int flags, const char *s);
void de_printf(deark *c, unsigned int flags, const char *fmt, ...)
	de_gnuc_attribute ((format (printf, 3, 4)));

void de_utf8_to_ascii(const char *src, char *dst, size_t dstlen, unsigned int flags);

#ifdef DE_WINDOWS
void de_utf8_to_oem(deark *c, const char *src, char *dst, size_t dstlen);
char **de_convert_args_to_utf8(int argc, wchar_t **argvW);
void de_free_utf8_args(int argc, char **argv);
wchar_t *de_utf8_to_utf16_strdup(deark *c, const char *src);
void de_utf8_to_utf16_to_FILE(deark *c, const char *src, FILE *f);
void *de_winconsole_get_handle(int n);
int de_winconsole_is_console(void *h1);
int de_get_current_windows_attributes(void *handle, unsigned int *attrs);
void de_windows_highlight(void *handle1, unsigned int orig_attr, int x);
#endif

void de_set_base_output_filename(deark *c, const char *fn);

void de_set_output_archive_filename(deark *c, const char *fn);
