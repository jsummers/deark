// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Functions specific to Unix and other non-Windows builds

#define DE_NOT_IN_MODULE
#include "deark-config.h"

#ifdef DE_UNIX

// This file is overloaded, in that it contains functions intended to only
// be used internally, as well as functions intended only for the
// command-line utility. That's why we need both deark-user.h and
// deark-private.h.
#include "deark-private.h"
#include "deark-user.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <utime.h>
#include <errno.h>

// Unix-specific contextual data, not currently used.
struct de_platform_data {
	int reserved;
};

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

i64 de_strtoll(const char *string, char **endptr, int base)
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
static int de_examine_file_by_fd(deark *c, int fd, i64 *len,
	char *errmsg, size_t errmsg_len, unsigned int *returned_flags)
{
	struct stat stbuf;

	*returned_flags = 0;
	de_zeromem(&stbuf, sizeof(struct stat));

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

	*len = (i64)stbuf.st_size;
	return 1;
}

FILE* de_fopen_for_read(deark *c, const char *fn, i64 *len,
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
	char *errmsg, size_t errmsg_len, int overwrite_mode,
	unsigned int flags)
{
	const char *mode;

	if(overwrite_mode!=DE_OVERWRITEMODE_STANDARD) {
		// Check if the file already exists.
		struct stat stbuf;
		int s_ret;

		de_zeromem(&stbuf, sizeof(struct stat));
		s_ret = lstat(fn, &stbuf);

		 // s_ret==0 = "success"
		if(s_ret==0 && overwrite_mode==DE_OVERWRITEMODE_NEVER) {
			de_strlcpy(errmsg, "Output file already exists", errmsg_len);
			return NULL;
		}

		if(s_ret==0 && overwrite_mode==DE_OVERWRITEMODE_DEFAULT) {
			if ((stbuf.st_mode & S_IFMT) == S_IFLNK) {
				de_strlcpy(errmsg, "Output file is a symlink", errmsg_len);
				return NULL;
			}
		}
	}

	mode = (flags&0x1) ? "ab" : "wb";
	return de_fopen(c, fn, mode, errmsg, errmsg_len);
}

int de_fseek(FILE *fp, i64 offs, int whence)
{
	int ret;

#ifdef DE_USE_FSEEKO
	ret = fseeko(fp, (off_t)offs, whence);
#else
	ret = fseek(fp, (long)offs, whence);
#endif
	return ret;
}

i64 de_ftell(FILE *fp)
{
	i64 ret;

#ifdef DE_USE_FSEEKO
	ret = (i64)ftello(fp);
#else
	ret = (i64)ftell(fp);
#endif
	return ret;
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
	if(!f->fi_copy) return;
	if(!f->name) return;
	if(!(f->fi_copy->mode_flags&DE_MODEFLAG_NONEXE) &&!(f->fi_copy->mode_flags&DE_MODEFLAG_EXE)) return;

	de_zeromem(&stbuf, sizeof(struct stat));
	if(0 != stat(f->name, &stbuf)) {
		return;
	}

	oldmode = stbuf.st_mode;
	newmode = oldmode;

	// Start by turning off the executable bits in the tentative new mode.
	newmode &= ~(S_IXUSR|S_IXGRP|S_IXOTH);

	if(f->fi_copy->mode_flags&DE_MODEFLAG_EXE) {
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
	const struct de_timestamp *ts;
	struct timeval times[2];

	if(f->btype!=DBUF_TYPE_OFILE) return;
	if(!f->fi_copy) return;
	ts = &f->fi_copy->mod_time;
	if(!ts->is_valid) return;
	if(!f->name) return;

	// I know that this code is not Y2038-compliant, if sizeof(time_t)==4.
	// But it's not likely to be a serious problem, and I'd rather not replace
	// it with code that's less portable.

	de_zeromem(&times, sizeof(times));
	// times[0] = access time
	times[0].tv_sec = (long)de_timestamp_to_unix_time(ts);
	if(ts->precision>DE_TSPREC_1SEC) {
		times[0].tv_usec = (long)(de_timestamp_get_subsec(ts)/10);
	}
	// times[1] = mod time
	times[1] = times[0];
	utimes(f->name, times);
}

// Note: Need to keep this function in sync with the implementation in deark-win.c.
void de_current_time_to_timestamp(struct de_timestamp *ts)
{
	struct timeval tv;
	int ret;

	de_zeromem(&tv, sizeof(struct timeval));
	ret = gettimeofday(&tv, NULL);
	if(ret!=0) {
		de_zeromem(ts, sizeof(struct de_timestamp));
		return;
	}

	de_unix_time_to_timestamp((i64)tv.tv_sec, ts, 0x1);
	de_timestamp_set_subsec(ts, ((double)tv.tv_usec)/1000000.0);
}

void de_exitprocess(void)
{
	exit(1);
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

#endif // DE_UNIX
