// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Functions specific to Unix and other non-Windows builds

#define DE_NOT_IN_MODULE
#include "deark-config.h"

#ifdef DE_WINDOWS
#error "This file is not for Windows builds"
#endif

// This file is overloaded, in that it contains functions intended to only
// be used internally, as well as functions intended only for the
// command-line utility. That's why we need both deark-user.h and
// deark-private.h.
#include "deark-private.h"
#include "deark-user.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <utime.h>
#include <errno.h>

int de_strcasecmp(const char *a, const char *b)
{
	return strcasecmp(a, b);
}

void de_vsnprintf(char *buf, size_t buflen, const char *fmt, va_list ap)
{
	vsnprintf(buf,buflen,fmt,ap);
	buf[buflen-1]='\0';
}

char *de_strdup(deark *c, const char *s)
{
	char *s2;

	s2 = strdup(s);
	if(!s2) {
		de_err(c, "Memory allocation failed");
		de_fatalerror(c);
		return NULL;
	}
	return s2;
}

de_int64 de_strtoll(const char *string, char **endptr, int base)
{
	return strtoll(string, endptr, base);
}

static FILE* de_fopen(deark *c, const char *fn, const char *mode,
	char *errmsg, size_t errmsg_len)
{
	FILE *f;
	int errcode;

	f = fopen(fn, mode);
	if(!f) {
		errcode = errno;
		de_strlcpy(errmsg, strerror(errcode), errmsg_len);
	}
	return f;
}

// Test if the file seems suitable for reading, and return its size.
// returned flags: 0x1 = file is a FIFO (named pipe)
static int de_examine_file_by_fd(deark *c, int fd, de_int64 *len,
	char *errmsg, size_t errmsg_len, unsigned int *returned_flags)
{
	struct stat stbuf;

	*returned_flags = 0;
	de_memset(&stbuf, 0, sizeof(struct stat));

	if(0 != fstat(fd, &stbuf)) {
		de_strlcpy(errmsg, strerror(errno), errmsg_len);
		return 0;
	}

	if(S_ISFIFO(stbuf.st_mode)) {
		*returned_flags |= 0x1;
		*len = 0;
		return 1;
	}
	else if(!S_ISREG(stbuf.st_mode)) {
		de_strlcpy(errmsg, "Not a regular file", errmsg_len);
		return 0;
	}

	*len = (de_int64)stbuf.st_size;
	return 1;
}

FILE* de_fopen_for_read(deark *c, const char *fn, de_int64 *len,
	char *errmsg, size_t errmsg_len, unsigned int *returned_flags)
{
	int ret;
	FILE *f;

	f = de_fopen(c, fn, "rb", errmsg, errmsg_len);
	if(!f) {
		return NULL;
	}

	ret = de_examine_file_by_fd(c, fileno(f), len, errmsg, errmsg_len,
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
	const char *mode;
	mode = (flags&0x1) ? "ab" : "wb";
	return de_fopen(c, fn, mode, errmsg, errmsg_len);
}

int de_fclose(FILE *fp)
{
	return fclose(fp);
}

// If, based on f->mode_flags, we know that the file should be executable or
// non-executable, make it so.
void de_update_file_perms(dbuf *f)
{
	struct stat stbuf;
	mode_t oldmode, newmode;

	if(f->btype!=DBUF_TYPE_OFILE) return;
	if(!f->name) return;
	if(!(f->mode_flags&DE_MODEFLAG_NONEXE) && !(f->mode_flags&DE_MODEFLAG_EXE)) return;

	de_memset(&stbuf, 0, sizeof(struct stat));
	if(0 != stat(f->name, &stbuf)) {
		return;
	}

	oldmode = stbuf.st_mode;
	newmode = oldmode;

	// Start by turning off the executable bits in the tentative new mode.
	newmode &= ~(S_IXUSR|S_IXGRP|S_IXOTH);

	if(f->mode_flags&DE_MODEFLAG_EXE) {
		// Set an Executable bit if its corresponding Read bit is set.
		if(oldmode & S_IRUSR) newmode |= S_IXUSR;
		if(oldmode & S_IRGRP) newmode |= S_IXGRP;
		if(oldmode & S_IROTH) newmode |= S_IXOTH;
	}

	if(newmode != oldmode) {
		de_dbg2(f->c, "changing file mode from %03o to %03o",
			(unsigned int)oldmode, (unsigned int)newmode);
		chmod(f->name, newmode);
	}
}

void de_update_file_time(dbuf *f)
{
	struct utimbuf times;

	if(f->btype!=DBUF_TYPE_OFILE) return;
	if(!f->mod_time.is_valid) return;
	if(!f->name) return;

	// I know that this code is not Y2038-compliant, if sizeof(time_t)==4.
	// But it's not likely to be a serious problem, and I'd rather not replace
	// it with code that's less portable.

	times.modtime = de_timestamp_to_unix_time(&f->mod_time);
	times.actime = times.modtime;
	utime(f->name, &times);
}

// Note: Need to keep this function in sync with the implementation in deark-win.c.
void de_timestamp_to_string(const struct de_timestamp *ts,
	char *buf, size_t buf_len, unsigned int flags)
{
	de_int64 tmpt_int64;
	time_t tmpt;
	struct tm *tm1;
	const char *tzlabel;

	if(!ts->is_valid) {
		de_strlcpy(buf, "[invalid timestamp]", buf_len);
		return;
	}

	tmpt_int64 = de_timestamp_to_unix_time(ts);

	if(sizeof(time_t)<=4) {
		if(tmpt_int64<-0x80000000LL || tmpt_int64>0x7fffffffLL) {
			// TODO: Support a wider range of timestamps.
			// See comment in deark-win.c.
			de_snprintf(buf, buf_len, "[timestamp out of range: %"INT64_FMT"]", tmpt_int64);
			return;
		}
	}

	tmpt = (time_t)tmpt_int64;
	tm1 = gmtime(&tmpt);

	tzlabel = (flags&0x1)?" UTC":"";
	de_snprintf(buf, buf_len, "%04d-%02d-%02d %02d:%02d:%02d%s",
		1900+tm1->tm_year, 1+tm1->tm_mon, tm1->tm_mday,
		tm1->tm_hour, tm1->tm_min, tm1->tm_sec, tzlabel);
}

// Note: Need to keep this function in sync with the implementation in deark-win.c.
void de_current_time_to_timestamp(struct de_timestamp *ts)
{
	time_t t;

	de_memset(ts, 0, sizeof(struct de_timestamp));
	time(&t);
	ts->unix_time = (de_int64)t;
	ts->is_valid = 1;
}

void de_exitprocess(void)
{
	exit(1);
}
