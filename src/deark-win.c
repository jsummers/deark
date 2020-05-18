// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Functions specific to Microsoft Windows, especially those that require
// windows.h.

#define DE_NOT_IN_MODULE
#include "deark-config.h"

#ifdef DE_WINDOWS

#include <windows.h>

#include <sys/stat.h>
#include <sys/types.h>

// This file is overloaded, in that it contains functions intended to only
// be used internally, as well as functions intended only for the
// command-line utility. That's why we need both deark-user.h and
// deark-private.h.
#include "deark-private.h"
#include "deark-user.h"

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

// Windows-specific contextual data, mainly for console settings.
struct de_platform_data {
	HANDLE msgs_HANDLE;
	int msgs_HANDLE_is_console;
	WORD orig_console_attribs;
	WORD inverse_console_attribs;
};

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

i64 de_strtoll(const char *string, char **endptr, int base)
{
	return _strtoi64(string, endptr, base);
}

void de_utf8_to_oem(deark *c, const char *src, char *dst, size_t dstlen)
{
	WCHAR *srcW;
	int ret;

	srcW = de_utf8_to_utf16_strdup(c, src);

	// FIXME: An issue is that WideCharToMultiByte translates some printable
	// Unicode characters to OEM graphics characters below 0x20. For example, for
	// CP437, U+000A (LINE FEED) and U+25D9 (INVERSE WHITE CIRCLE) are both
	// translated to 0x0a.
	// The printf-like functions we will use on the translated string interpret
	// bytes below 0x20 as ASCII control characters, so U+25D9 will end up being
	// misinterpreted as a newline.
	// I am not sure what to do about this. It might be possible to change the
	// mode that printf uses, but we at least need newlines to work.
	// Ideally, we should probably redesign some things so that de_utf8_to_oem()
	// is not used with strings that contain newlines. But that's a lot of work
	// for an obscure feature.
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
	dst = (char*)de_malloc(c, dstlen);

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
	dst = (WCHAR*)de_mallocarray(c, dstlen, sizeof(WCHAR));

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

static FILE* de_fopenW(deark *c, const WCHAR *fnW, const WCHAR *modeW,
	char *errmsg, size_t errmsg_len)
{
	FILE *f = NULL;
	errno_t errcode;

	errcode = _wfopen_s(&f, fnW, modeW);

	errmsg[0] = '\0';

	if(errcode!=0) {
		strerror_s(errmsg, (size_t)errmsg_len, (int)errcode);
		f=NULL;
	}
	return f;
}

static int de_examine_file_by_fd(deark *c, int fd, i64 *len,
	char *errmsg, size_t errmsg_len, unsigned int *returned_flags)
{
	struct __stat64 stbuf;
	int retval = 0;

	*returned_flags = 0;

	de_zeromem(&stbuf, sizeof(struct __stat64));

	if(0 != _fstat64(fd, &stbuf)) {
		strerror_s(errmsg, (size_t)errmsg_len, errno);
		goto done;
	}

	if(!(stbuf.st_mode & _S_IFREG)) {
		de_strlcpy(errmsg, "Not a regular file", errmsg_len);
		return 0;
	}

	*len = (i64)stbuf.st_size;

	retval = 1;

done:
	return retval;
}

FILE* de_fopen_for_read(deark *c, const char *fn, i64 *len,
	char *errmsg, size_t errmsg_len, unsigned int *returned_flags)
{
	int ret;
	FILE *f;
	WCHAR *fnW;

	fnW = de_utf8_to_utf16_strdup(c, fn);

	f = de_fopenW(c, fnW, L"rb", errmsg, errmsg_len);

	de_free(c, fnW);

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
	char *errmsg, size_t errmsg_len, int overwrite_mode,
	unsigned int flags)
{
	const WCHAR *modeW;
	WCHAR *fnW = NULL;
	FILE *f_ret = NULL;

	// A simple check to make it harder to accidentally overwrite the input
	// file. (But it can easily be defeated.)
	// TODO?: Make this more robust.
	if(c->input_filename && !de_strcasecmp(fn, c->input_filename)) {
		de_err(c, "Refusing to write to %s: Same as input filename", fn);
		de_fatalerror(c);
		de_strlcpy(errmsg, "", errmsg_len);
		goto done;
	}

	modeW = (flags&0x1) ? L"ab" : L"wb";
	fnW = de_utf8_to_utf16_strdup(c, fn);

	if(overwrite_mode==DE_OVERWRITEMODE_NEVER) {
		DWORD fa = GetFileAttributesW(fnW);
		if(fa != INVALID_FILE_ATTRIBUTES) {
			de_strlcpy(errmsg, "Output file already exists", errmsg_len);
			goto done;
		}
	}

	f_ret = de_fopenW(c, fnW, modeW, errmsg, errmsg_len);

done:
	de_free(c, fnW);
	return f_ret;
}

int de_fseek(FILE *fp, i64 offs, int whence)
{
	return _fseeki64(fp, (__int64)offs, whence);
}

i64 de_ftell(FILE *fp)
{
	return (i64)_ftelli64(fp);
}

int de_fclose(FILE *fp)
{
	return fclose(fp);
}

static void update_file_time(dbuf *f)
{
	WCHAR *fnW = NULL;
	HANDLE fh = INVALID_HANDLE_VALUE;
	i64 ft;
	FILETIME wrtime;
	deark *c;

	if(f->btype!=DBUF_TYPE_OFILE) return;
	if(!f->fi_copy) return;
	if(!f->fi_copy->timestamp[DE_TIMESTAMPIDX_MODIFY].is_valid) return;
	if(!f->name) return;
	c = f->c;

	ft = de_timestamp_to_FILETIME(&f->fi_copy->timestamp[DE_TIMESTAMPIDX_MODIFY]);
	if(ft==0) goto done;
	fnW = de_utf8_to_utf16_strdup(c, f->name);
	fh = CreateFileW(fnW, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(fh==INVALID_HANDLE_VALUE) goto done;

	wrtime.dwHighDateTime = (DWORD)(((u64)ft)>>32);
	wrtime.dwLowDateTime = (DWORD)(((u64)ft)&0xffffffffULL);
	SetFileTime(fh, NULL, NULL, &wrtime);

done:
	if(fh != INVALID_HANDLE_VALUE) {
		CloseHandle(fh);
	}
	de_free(c, fnW);
}

void de_update_file_attribs(dbuf *f, u8 preserve_file_times)
{
	// [Updating file permissions not implemented on Windows.]

	if(preserve_file_times) {
		update_file_time(f);
	}
}

char **de_convert_args_to_utf8(int argc, wchar_t **argvW)
{
	int i;
	char **argvUTF8;

	argvUTF8 = (char**)de_mallocarray(NULL, argc, sizeof(char*));

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

struct de_platform_data *de_platformdata_create(void)
{
	struct de_platform_data *plctx;

	plctx = de_malloc(NULL, sizeof(struct de_platform_data));
	return plctx;
}

void de_platformdata_destroy(struct de_platform_data *plctx)
{
	if(!plctx) return;
	de_free(NULL, plctx);
}

// Set the plctx->msgs_HANDLE field, for later use.
// n: 1=stdout, 2=stderr
void de_winconsole_init_handle(struct de_platform_data *plctx, int n)
{
	DWORD consolemode=0;
	BOOL b;

	plctx->msgs_HANDLE = GetStdHandle((n==2)?STD_ERROR_HANDLE:STD_OUTPUT_HANDLE);

	b = GetConsoleMode(plctx->msgs_HANDLE, &consolemode);
	plctx->msgs_HANDLE_is_console = b ? 1 : 0;
}

// Does plctx->msgs_HANDLE seem to be a Windows console?
int de_winconsole_is_console(struct de_platform_data *plctx)
{
	return plctx->msgs_HANDLE_is_console;
}

void de_winconsole_set_UTF8_CP(struct de_platform_data *plctx)
{
	// I hate to do this, but it's the least bad fix I've found for some issues
	// that have cropped up in the wake of Cygwin+Mintty using Windows 10's
	// ConPTY features (as of Cygwin 3.1.0 - Dec. 2019).

	// Note that, somewhat ironically, we only change the console code page if
	// the output is *not* going directly to a console.

	// Unfortunately, rude as it is not to do so, we can't restore the original
	// code page settings when we're done. If we restore the code page, we have
	// do it after all of the output has reached the console. But if our output
	// is being piped through a pager, some of it likely won't reach the console
	// until after our program ends.
	SetConsoleCP(65001);
	SetConsoleOutputCP(65001);
}

// Save current attribs to plctx.
// Returns 1 on success.
void de_winconsole_record_current_attributes(struct de_platform_data *plctx)
{
	CONSOLE_SCREEN_BUFFER_INFO csbi;

	if(GetConsoleScreenBufferInfo(plctx->msgs_HANDLE, &csbi)) {
		plctx->orig_console_attribs = csbi.wAttributes;
	}
	else {
		plctx->orig_console_attribs = 0x0007;
	}

	plctx->inverse_console_attribs =
		(plctx->orig_console_attribs&0xff00) |
		((plctx->orig_console_attribs&0x000f)<<4) |
		((plctx->orig_console_attribs&0x00f0)>>4);
}

// If we think this computer supports 24-bit color ANSI, enable it (if needed)
// and return 1.
// Otherwise return 0.
int de_winconsole_try_enable_ansi24(struct de_platform_data *plctx)
{
	// Note: Maybe we should check for Windows 10 (e.g. using
	// IsWindows10OrGreater()) before calling SetConsoleMode(), but maybe that's
	// just be a waste of time. Also, IsWindows10OrGreater() is fragile because
	// it requires a .manifest file with certain properties.

	// TODO: This is not correct. AFAIK, there is a range of Windows 10 builds
	// that support ANSI codes, but do not support 24-bit color ANSI.
	// I don't know a *good* way to detect 24-bit color support.
	// Querying the Windows build number is possible, but requires some hackery,
	// because Microsoft *really* does not want applications to do that.
	return de_winconsole_enable_ansi(plctx);
}

int de_winconsole_enable_ansi(struct de_platform_data *plctx)
{
	BOOL b;
	DWORD oldmode = 0;

	if(!plctx->msgs_HANDLE_is_console) return 1;

	b = GetConsoleMode(plctx->msgs_HANDLE, &oldmode);
	if(!b) return 0;
	if(oldmode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) return 1; // Already enabled

	// The ENABLE_VIRTUAL_TERMINAL_PROCESSING mode is what enables interpretation
	// of ANSI escape codes.

	// Note: This mode seems to be specific to the console window, not to the specific
	// I/O handle that we pass to SetConsoleMode.
	// I.e. if both stderr and stdout refer to the console, it doesn't matter which
	// one we use here.
	// And if we write an ANSI code to stderr, it could also affect stdout.
	// That's not what we want, but it shouldn't cause much of a problem for us.

	// Note: This mode seems to get reset automatically when the process ends.
	// It doesn't affect future processes that run in the same console.
	// So we don't have to try to set it back when we're done.

	b = SetConsoleMode(plctx->msgs_HANDLE, oldmode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
	if(!b) return 0;
	return 1;
}

void de_winconsole_highlight(struct de_platform_data *plctx, int x)
{
	if(x) {
		SetConsoleTextAttribute(plctx->msgs_HANDLE, plctx->inverse_console_attribs);
	}
	else {
		SetConsoleTextAttribute(plctx->msgs_HANDLE, plctx->orig_console_attribs);
	}
}

// Note: Need to keep this function in sync with the implementation in deark-unix.c.
void de_current_time_to_timestamp(struct de_timestamp *ts)
{
	FILETIME ft1;
	i64 ft;

	GetSystemTimeAsFileTime(&ft1);
	ft = (i64)(((u64)ft1.dwHighDateTime)<<32 | ft1.dwLowDateTime);
	de_FILETIME_to_timestamp(ft, ts, 0x1);
}

void de_exitprocess(int s)
{
	exit(s);
}

#endif // DE_WINDOWS
