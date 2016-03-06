// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Functions specific to Unix and other non-Windows builds

#include "deark-config.h"

#ifdef DE_WINDOWS
#error "This file is not for Windows builds"
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <utime.h>
#include <errno.h>

#include "deark-private.h"

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
		de_err(c, "Memory allocation failed\n");
		de_fatalerror(c);
	}
	return s2;
}

de_int64 de_strtoll(const char *string, char **endptr, int base)
{
	return strtoll(string, endptr, base);
}

FILE* de_fopen(deark *c, const char *fn, const char *mode,
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

int de_fclose(FILE *fp)
{
	return fclose(fp);
}

int de_examine_file_by_name(deark *c, const char *fn, de_int64 *len,
	char *errmsg, size_t errmsg_len)
{
	struct stat stbuf;

	de_memset(&stbuf, 0, sizeof(struct stat));

	if(0 != stat(fn, &stbuf)) {
		de_strlcpy(errmsg, strerror(errno), errmsg_len);
		return 0;
	}

	if(!S_ISREG(stbuf.st_mode)) {
		de_strlcpy(errmsg, "Not a regular file", errmsg_len);
		return 0;
	}

	*len = (de_int64)stbuf.st_size;
	return 1;
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
	time_t tmpt;
	struct tm *tm1;
	const char *tzlabel;

	if(!ts->is_valid) {
		de_strlcpy(buf, "[invalid timestamp]", buf_len);
		return;
	}

	tmpt = (time_t)de_timestamp_to_unix_time(ts);
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
