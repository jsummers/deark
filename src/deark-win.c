// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Functions specific to Microsoft Windows, especially those that require
// windows.h.

#define DE_NOT_IN_MODULE
#include "deark-config.h"

#ifndef DE_WINDOWS
#error "This file is only for Windows builds"
#endif

#include <windows.h>

// This file is overloaded, in that it contains functions intended to only
// be used internally, as well as functions intended only for the
// command-line utility. That's why we need both deark-user.h and
// deark-private.h.
#include "deark-private.h"
#include "deark-user.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <sys/utime.h>

int de_strcasecmp(const char *a, const char *b)
{
	return _stricmp(a, b);
}

void de_vsnprintf(char *buf, size_t buflen, const char *fmt, va_list ap)
{
	_vsnprintf_s(buf, buflen, _TRUNCATE, fmt, ap);
}

char *de_strdup(deark *c, const char *s)
{
	char *s2;

	s2 = _strdup(s);
	if(!s2) {
		de_err(c, "Memory allocation failed");
		de_fatalerror(c);
		return NULL;
	}
	return s2;
}

de_int64 de_strtoll(const char *string, char **endptr, int base)
{
	return _strtoi64(string, endptr, base);
}

void de_utf8_to_oem(deark *c, const char *src, char *dst, size_t dstlen)
{
	WCHAR *srcW;
	int ret;

	srcW = de_utf8_to_utf16_strdup(c, src);

	ret = WideCharToMultiByte(CP_OEMCP, 0, srcW, -1, dst, (int)dstlen, NULL, NULL);
	if(ret<1) {
		dst[0]='\0';
	}

	de_free(c, srcW);
}

static char *de_utf16_to_utf8_strdup(deark *c, const WCHAR *src)
{
	char *dst;
	int dstlen;
	int ret;

	// Calculate the size required by the target string.
	ret = WideCharToMultiByte(CP_UTF8, 0, src, -1, NULL, 0, NULL, NULL);
	if(ret<1) return NULL;

	dstlen = ret;
	dst = (char*)de_malloc(c, dstlen*sizeof(char));

	ret = WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, dstlen, NULL, NULL);
	if(ret<1) {
		de_free(c, dst);
		return NULL;
	}
	return dst;
}

wchar_t *de_utf8_to_utf16_strdup(deark *c, const char *src)
{
	WCHAR *dst;
	int dstlen;
	int ret;

	// Calculate the size required by the target string.
	ret = MultiByteToWideChar(CP_UTF8, 0, src, -1, NULL, 0);
	if(ret<1) {
		de_err(c, "Encoding conversion failed");
		de_fatalerror(c);
		return NULL;
	}

	dstlen = ret;
	dst = (WCHAR*)de_malloc(c, dstlen*sizeof(WCHAR));

	ret = MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, dstlen);
	if(ret<1) {
		de_free(c, dst);
		de_err(c, "Encoding conversion failed");
		de_fatalerror(c);
		return NULL;
	}
	return dst;
}

// Convert a string from utf8 to utf16, then write it to a FILE
// (e.g. using fputws).
void de_utf8_to_utf16_to_FILE(deark *c, const char *src, FILE *f)
{
#define DST_SMALL_SIZE 1024
	WCHAR dst_small[DST_SMALL_SIZE];
	WCHAR *dst_large;
	int ret;

	ret = MultiByteToWideChar(CP_UTF8, 0, src, -1, dst_small, DST_SMALL_SIZE);
	if(ret>=1) {
		// Our "small" buffer was big enough for the converted string.
		fputws(dst_small, f);
		return;
	}

	// Our "small" buffer was not big enough. Do it the slow way.
	// (Unfortunately, MultiByteToWideChar doesn't have a way to automatically
	// tell us the required buffer size in the case that the supplied buffer
	// was not big enough. So we end up calling it three times, when two should
	// have been sufficient. But this is a rare code path.)
	dst_large = de_utf8_to_utf16_strdup(c, src);
	fputws(dst_large, f);
	de_free(c, dst_large);
}

static FILE* de_fopen(deark *c, const char *fn, const WCHAR *modeW,
	char *errmsg, size_t errmsg_len)
{
	FILE *f = NULL;
	errno_t errcode;
	WCHAR *fnW;

	fnW = de_utf8_to_utf16_strdup(c, fn);

	errcode = _wfopen_s(&f, fnW, modeW);

	de_free(c, fnW);

	errmsg[0] = '\0';

	if(errcode!=0) {
		strerror_s(errmsg, (size_t)errmsg_len, (int)errcode);
		f=NULL;
	}
	return f;
}

static int de_examine_file_by_fd(deark *c, int fd, de_int64 *len,
	char *errmsg, size_t errmsg_len, unsigned int *returned_flags)
{
	struct __stat64 stbuf;
	int retval = 0;

	*returned_flags = 0;

	de_memset(&stbuf, 0, sizeof(struct __stat64));

	if(0 != _fstat64(fd, &stbuf)) {
		strerror_s(errmsg, (size_t)errmsg_len, errno);
		goto done;
	}

	if(!(stbuf.st_mode & _S_IFREG)) {
		de_strlcpy(errmsg, "Not a regular file", errmsg_len);
		return 0;
	}

	*len = (de_int64)stbuf.st_size;

	retval = 1;

done:
	return retval;
}

FILE* de_fopen_for_read(deark *c, const char *fn, de_int64 *len,
	char *errmsg, size_t errmsg_len, unsigned int *returned_flags)
{
	int ret;
	FILE *f;

	f = de_fopen(c, fn, L"rb", errmsg, errmsg_len);
	if(!f) {
		return NULL;
	}

	ret = de_examine_file_by_fd(c, _fileno(f), len, errmsg, errmsg_len,
		returned_flags);
	if(!ret) {
		de_fclose(f);
		return NULL;
	}

	return f;
}

// flags: 0x1 = append instead of overwriting
FILE* de_fopen_for_write(deark *c, const char *fn,
	char *errmsg, size_t errmsg_len, unsigned int flags)
{
	const WCHAR *modeW;
	modeW = (flags&0x1) ? L"ab" : L"wb";
	return de_fopen(c, fn, modeW, errmsg, errmsg_len);
}

int de_fclose(FILE *fp)
{
	return fclose(fp);
}

void de_update_file_perms(dbuf *f)
{
	// Not implemented on Windows.
}

void de_update_file_time(dbuf *f)
{
	WCHAR *fnW;
	struct __utimbuf64 times;
	deark *c;

	if(f->btype!=DBUF_TYPE_OFILE) return;
	if(!f->mod_time.is_valid) return;
	if(!f->name) return;
	c = f->c;

	fnW = de_utf8_to_utf16_strdup(c, f->name);

	times.modtime = de_timestamp_to_unix_time(&f->mod_time);
	times.actime = times.modtime;
	_wutime64(fnW, &times);

	de_free(c, fnW);
}

char **de_convert_args_to_utf8(int argc, wchar_t **argvW)
{
	int i;
	char **argvUTF8;

	argvUTF8 = (char**)de_malloc(NULL, argc*sizeof(char*));

	// Convert parameters to UTF-8
	for(i=0;i<argc;i++) {
		argvUTF8[i] = de_utf16_to_utf8_strdup(NULL, argvW[i]);
	}

	return argvUTF8;
}

void de_free_utf8_args(int argc, char **argv)
{
	int i;

	for(i=0;i<argc;i++) {
		de_free(NULL, argv[i]);
	}
	de_free(NULL, argv);
}

// Return an output HANDLE that can be passed to other winconsole functions.
// n: 1=stdout, 2=stderr
void *de_winconsole_get_handle(int n)
{
	return (void*)GetStdHandle((n==2)?STD_ERROR_HANDLE:STD_OUTPUT_HANDLE);
}

// Does the given HANDLE (cast to void*) seem to be a Windows console?
int de_winconsole_is_console(void *h1)
{
	DWORD consolemode=0;
	BOOL n;

	n=GetConsoleMode((HANDLE)h1, &consolemode);
	return n ? 1 : 0;
}

int de_get_current_windows_attributes(void *handle, unsigned int *attrs)
{
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	if(!GetConsoleScreenBufferInfo((HANDLE)handle, &csbi))
		return 0;
	*attrs = (unsigned int)csbi.wAttributes;
	return 1;
}

void de_windows_highlight(void *handle1, unsigned int orig_attr, int x)
{
	if(x) {
		SetConsoleTextAttribute((void*)handle1,
			(orig_attr&0xff00) |
			((orig_attr&0x000fU)<<4) |
			((orig_attr&0x00f0U)>>4) );
	}
	else {
		SetConsoleTextAttribute((void*)handle1, (WORD)orig_attr);
	}
}

// Note: Need to keep this function in sync with the implementation in deark-unix.c.
void de_timestamp_to_string(const struct de_timestamp *ts,
	char *buf, size_t buf_len, unsigned int flags)
{
	de_int64 tmpt_int64;
	__time64_t tmpt;
	struct tm tm1;
	const char *tzlabel;
	errno_t ret;

	if(!ts->is_valid) {
		de_strlcpy(buf, "[invalid timestamp]", buf_len);
		return;
	}

	de_memset(&tm1, 0, sizeof(struct tm));
	tmpt_int64 = de_timestamp_to_unix_time(ts);
	tmpt = (__time64_t)tmpt_int64;

	// _gmtime64_s is documented as supporting times in the range:
	//  1970-01-01 00:00:00 UTC, through
	//  3000-12-31 23:59:59 UTC.
	// I tested it, and on my computer it worked from:
	//  1969-12-31 12:00:00 UTC, through
	//  3001-01-01 20:59:59 UTC.
	// [The behavior of _gmtime64_s does not depend on the user's current
	// timezone settings, right? I hope?]
	// TODO: At the very least, we need to support the range ~1900 to 2108,
	// to cover most of the traditional formats. We probably need a custom
	// gmtime function.
	ret = _gmtime64_s(&tm1, &tmpt);
	if(ret!=0) {
		de_snprintf(buf, buf_len, "[timestamp out of range: %"INT64_FMT"]", tmpt_int64);
		return;
	}

	tzlabel = (flags&0x1)?" UTC":"";
	de_snprintf(buf, buf_len, "%04d-%02d-%02d %02d:%02d:%02d%s",
		1900+tm1.tm_year, 1+tm1.tm_mon, tm1.tm_mday,
		tm1.tm_hour, tm1.tm_min, tm1.tm_sec, tzlabel);
}

// Note: Need to keep this function in sync with the implementation in deark-unix.c.
void de_current_time_to_timestamp(struct de_timestamp *ts)
{
	__time64_t t;

	de_memset(ts, 0, sizeof(struct de_timestamp));
	_time64(&t);
	ts->unix_time = (de_int64)t;
	ts->is_valid = 1;
}

void de_exitprocess(void)
{
	exit(1);
}
