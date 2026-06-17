// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Functions specific to Unix and other non-Windows builds

#define DE_NOT_IN_MODULE
#include "deark-config.h"

#ifdef DE_UNIX

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <utime.h>
#include <errno.h>

// This file is overloaded, in that it contains functions intended to only
// be used internally, as well as functions intended only for the
// command-line utility. That's why we need both deark-user.h and
// deark-private.h.
#include "deark-private.h"
#include "deark-user.h"

// Unix-specific contextual data, not currently used.
struct de_platform_data {
	int reserved;
};

void de_vsnprintf(char *buf, size_t buflen, const char *fmt, va_list ap)
{
	vsnprintf(buf,buflen,fmt,ap);
	buf[buflen-1]='\0';
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

// fop->out_flags: 0x1 = file is a FIFO (named pipe)
static int de_examine_file_by_fd(struct de_fopen_params *fop, int fd)
{
	struct stat stbuf;

	de_zeromem(&stbuf, sizeof(struct stat));

	if(0 != fstat(fd, &stbuf)) {
		de_strlcpy(fop->errmsg, strerror(errno), sizeof(fop->errmsg));
		return 0;
	}

	if(S_ISFIFO(stbuf.st_mode)) {
		fop->out_flags |= 0x1;
		fop->len = 0;
		return 1;
	}
	else if(!S_ISREG(stbuf.st_mode)) {
		de_strlcpy(fop->errmsg, "Not a regular file", sizeof(fop->errmsg));
		return 0;
	}

	fop->len = (i64)stbuf.st_size;

#if DE_USE_MTIMENSEC
	de_unix_time_to_timestamp(stbuf.st_mtime, &fop->orig_modtime, 0);
	de_timestamp_set_subsec(&fop->orig_modtime,
		(double)stbuf.st_mtimensec/1000000000.0);
	de_unix_time_to_timestamp(stbuf.st_atime, &fop->orig_acctime, 0);
	de_timestamp_set_subsec(&fop->orig_acctime,
		(double)stbuf.st_atimensec/1000000000.0);
#elif DE_USE_MTIM
	de_unix_time_to_timestamp(stbuf.st_mtim.tv_sec, &fop->orig_modtime, 0);
	de_timestamp_set_subsec(&fop->orig_modtime,
		(double)stbuf.st_mtim.tv_nsec/1000000000.0);
	de_unix_time_to_timestamp(stbuf.st_atim.tv_sec, &fop->orig_acctime, 0);
	de_timestamp_set_subsec(&fop->orig_acctime,
		(double)stbuf.st_atim.tv_nsec/1000000000.0);
#else
	de_unix_time_to_timestamp(stbuf.st_mtime, &fop->orig_modtime, 0);
	de_unix_time_to_timestamp(stbuf.st_atime, &fop->orig_acctime, 0);
#endif

	return 1;
}

void de_fopen_for_read(struct de_fopen_params *fop)
{
	int ret;

	fop->f = de_fopen(fop->c, fop->fn, "rb", fop->errmsg, sizeof(fop->errmsg));
	if(!fop->f) {
		return;
	}

	ret = de_examine_file_by_fd(fop, fileno(fop->f));
	if(!ret) {
		de_fclose(fop->f);
		fop->f = NULL;
		return;
	}
}

// flags: 0x1 = append instead of overwriting
FILE* de_fopen_for_write(deark *c, const char *fn,
	char *errmsg, size_t errmsg_len, int overwrite_mode,
	UI flags)
{
	const char *mode;

	// A simple check to make it harder to accidentally overwrite the input
	// file. (But it can easily be defeated.)
	// TODO?: Make this more robust.
	if(c->input_filename && !de_strcmp(fn, c->input_filename)) {
		de_err(c, "Refusing to write to %s: Same as input filename", fn);
		de_fatalerror(c);
		de_strlcpy(errmsg, "", errmsg_len);
		return NULL;
	}

	if(overwrite_mode!=DE_OVERWRITEMODE_STANDARD) {
		// Check if the file already exists.
		struct stat stbuf;
		int s_ret;

		de_zeromem(&stbuf, sizeof(struct stat));
#if DE_USE_LSTAT
		s_ret = lstat(fn, &stbuf);
#else
		s_ret = stat(fn, &stbuf);
#endif

		 // s_ret==0 = "success"
		if(s_ret==0 && overwrite_mode==DE_OVERWRITEMODE_NEVER) {
			de_strlcpy(errmsg, "Output file already exists", errmsg_len);
			return NULL;
		}

		if(s_ret==0 && overwrite_mode==DE_OVERWRITEMODE_DEFAULT) {
			if(S_ISLNK(stbuf.st_mode)) {
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

#if DE_USE_FSEEKO
	ret = fseeko(fp, (off_t)offs, whence);
#else
	ret = fseek(fp, (long)offs, whence);
#endif
	return ret;
}

i64 de_ftell(FILE *fp)
{
	i64 ret;

#if DE_USE_FSEEKO
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

struct upd_attr_ctx {
	int tried_stat;
	int stat_ret;
	struct stat stbuf;
};

// If, based on f->mode_flags, we know that the file should be executable or
// non-executable, make it so.
static void update_file_perms(struct upd_attr_ctx *uactx, dbuf *f)
{
	mode_t oldmode, newmode;

	if(f->btype!=DBUF_TYPE_OFILE) return;
	if(!f->fi_copy) return;
	if(!f->name) return;
	if(!(f->fi_copy->mode_flags&DE_MODEFLAG_NONEXE) &&!(f->fi_copy->mode_flags&DE_MODEFLAG_EXE)) return;

	uactx->stat_ret = stat(f->name, &uactx->stbuf);
	uactx->tried_stat = 1;
	if(uactx->stat_ret != 0) {
		return;
	}

	oldmode = uactx->stbuf.st_mode;
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

static void update_file_time(struct upd_attr_ctx *uactx, dbuf *f)
{
	const struct de_timestamp *ts[2];
	struct timeval times[2];

	if(f->btype!=DBUF_TYPE_OFILE) return;
	if(!f->fi_copy) return;
	ts[0] = &f->fi_copy->timestamp[DE_TIMESTAMPIDX_ACCESS];
	ts[1] = &f->fi_copy->timestamp[DE_TIMESTAMPIDX_MODIFY];
	if(!ts[1]->is_valid) return;
	if(!f->name) return;

	if(!uactx->tried_stat) {
		uactx->stat_ret = stat(f->name, &uactx->stbuf);
		uactx->tried_stat = 1;
	}

	de_zeromem(&times, sizeof(times));
	// times[0] = access time
	// times[1] = mod time
	times[1].tv_sec = (time_t)de_timestamp_to_unix_time(ts[1]);
	if(ts[1]->precision>DE_TSPREC_1SEC) {
		times[1].tv_usec = (suseconds_t)(de_timestamp_get_subsec(ts[1])/10);
	}

	// We don't always want to set the access time, but unfortunately the utimes()
	// function forces us to.
	if(ts[0]->is_valid) {
		times[0].tv_sec = (time_t)de_timestamp_to_unix_time(ts[0]);
		if(ts[0]->precision>DE_TSPREC_1SEC) {
			times[0].tv_usec = (suseconds_t)(de_timestamp_get_subsec(ts[0])/10);
		}
	}
	else if(uactx->tried_stat && (uactx->stat_ret==0)) {
		// If we have the file's current access time recorded, use that.
		times[0].tv_sec = uactx->stbuf.st_atime;
		times[0].tv_usec = 0;
	}
	else {
		// Otherwise use the mod time.
		times[0] = times[1];
	}
	utimes(f->name, times);
}

void de_update_file_attribs1(dbuf *f)
{
	return;
}

void de_update_file_attribs2(dbuf *f)
{
	struct upd_attr_ctx uactx;
	u8 preserve_file_times;

	de_zeromem(&uactx, sizeof(struct upd_attr_ctx));

	preserve_file_times = (f->fi_copy &&
		f->fi_copy->timestamp[DE_TIMESTAMPIDX_MODIFY].is_valid);
	update_file_perms(&uactx, f);
	if(preserve_file_times) {
		update_file_time(&uactx, f);
	}
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

void de_exitprocess(int s)
{
	exit(s?EXIT_FAILURE:EXIT_SUCCESS);
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
