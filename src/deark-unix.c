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

int de_get_file_size(FILE *fp, de_int64 *pfsize)
{
	struct stat stbuf;

	if(fstat(fileno(fp),&stbuf)==0) {
		*pfsize = stbuf.st_size;
		return 1;
	}
	*pfsize = 0;
	return 0;
}

void de_update_file_time(dbuf *f)
{
	struct utimbuf times;

	if(f->btype!=DBUF_TYPE_OFILE) return;
	if(!f->mod_time_valid) return;
	if(!f->name) return;

	// I know that this code is not Y2038-compliant, if sizeof(time_t)==4.
	// But it's not likely to be a serious problem, and I'd rather not replace
	// it with code that's less portable.

	times.modtime = f->mod_time;
	times.actime = times.modtime;
	utime(f->name, &times);
}
