// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// TAR format output

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"

struct tar_md {
	u8 need_exthdr_name;
	size_t namelen;
	i64 headers_pos;
	i64 headers_size;
	i64 checksum_calc;
	i64 modtime_unix;
};

struct tar_ctx {
	const char *tar_filename;
	dbuf *outf;

	// Data associated with current member file
	struct tar_md md;
};

int de_tar_create_file(deark *c)
{
	struct tar_ctx *tctx = NULL;
	int retval = 0;

	if(c->tar_data) return 1;

	tctx = de_malloc(c, sizeof(struct tar_ctx));
	c->tar_data = (void*)tctx;

	if(c->archive_to_stdout) {
		tctx->tar_filename = "[stdout]";
		de_err(c, "TAR to stdout is not implemented");
		de_fatalerror(c);
		goto done;
	}


	if(c->output_archive_filename) {
		tctx->tar_filename = c->output_archive_filename;
	}
	else {
		tctx->tar_filename = "output.tar";
	}

	de_info(c, "Creating %s", tctx->tar_filename);
	tctx->outf = dbuf_create_unmanaged_file(c, tctx->tar_filename,
		c->overwrite_mode, 0);

	if(tctx->outf->btype==DBUF_TYPE_NULL) {
		de_fatalerror(c);
		goto done;
	}

	retval = 1;

done:
	return retval;
}

void de_tar_close_file(deark *c)
{
	struct tar_ctx *tctx = (struct tar_ctx *)c->tar_data;

	if(!tctx) return;
	if(tctx->outf) {
		dbuf_write_zeroes(tctx->outf, 512*2);
		dbuf_close(tctx->outf);
	}
	de_free(c, tctx);
	c->tar_data = NULL;
}

// f is type DBUF_TYPE_ODBUF, in the process of being created.
// We are responsible for setting f->parent_dbuf and
// f->offset_into_parent_dbuf.
void de_tar_start_member_file(deark *c, dbuf *f)
{
	struct tar_ctx *tctx = NULL;

	if(!c->tar_data) {
		de_tar_create_file(c);
	}
	tctx = (struct tar_ctx *)c->tar_data;
	if(!tctx) return;
	de_zeromem(&tctx->md, sizeof(struct tar_md));

	f->parent_dbuf = tctx->outf;

	tctx->md.headers_pos = tctx->outf->len;

	tctx->md.namelen = de_strlen(f->name);
	if(tctx->md.namelen>100) {
		tctx->md.need_exthdr_name = 1;
	}

	tctx->md.headers_size = 512 /* *3 */;
	// Reserve space for the tar headers. We won't know the member file size
	// until it has been completely written, so we can't write the headers
	// yet. Instead we'll write them to headers_tmpdbuf, and seek back later
	// and patch them into the main tar file.
	dbuf_write_zeroes(tctx->outf, tctx->md.headers_size);

	f->offset_into_parent_dbuf = tctx->outf->len;
}

static int format_ascii_octal_field(deark *c, struct tar_ctx *tctx,
	i64 val, u8 *buf2, size_t buf2len)
{
	char buf1[32]; // The largest field we need to support is 12 bytes
	size_t k;
	size_t len_in_octal;

	de_zeromem(buf2, buf2len);
	if(buf2len>12) return 0;
	de_snprintf(buf1, sizeof(buf1), "%"U64_FMTo, (u64)val);
	len_in_octal = de_strlen(buf1);
	if(len_in_octal > buf2len) {
		for(k=0; k<buf2len; k++) {
			buf2[k] = '7';
		}
	}
	else if(len_in_octal == buf2len) {
		de_memcpy(buf2, buf1, buf2len);
	}
	else {
		size_t num_leading_0s = buf2len - 1 - len_in_octal;

		for(k=0; k<buf2len; k++) {
			if(k < num_leading_0s) {
				buf2[k] = '0';
			}
			else if(k < buf2len - 1) {
				buf2[k] = buf1[k-num_leading_0s];
			}
			else {
				buf2[k] = '\0';
			}
		}
	}

	return 1;
}

static int cksum_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	struct tar_md *md = (struct tar_md*)brctx->userdata;
	i64 i;

	for(i=0; i<buf_len; i++) {
		if((brctx->offset+i) >=148 && (brctx->offset+i)<156)
			md->checksum_calc += 32; // (The checksum field itself)
		else
			md->checksum_calc += (i64)buf[i];
	}

	return 1;
}

// Set the checksum field for the header starting at 'pos'.
static void set_checksum_field(deark *c, struct tar_ctx *tctx,
	dbuf *hdrs, i64 pos)
{
	u8 buf[8];

	tctx->md.checksum_calc = 0;
	dbuf_buffered_read(hdrs, pos, 512, cksum_cbfn, (void*)&tctx->md);

	format_ascii_octal_field(c, tctx, tctx->md.checksum_calc, buf, 7);
	buf[6] = 0x00;
	buf[7] = 0x20;
	dbuf_write_at(hdrs, 148, buf, 8);
}

static void format_and_append_ascii_field(deark *c, struct tar_ctx *tctx,
	const char *val_sz, size_t fieldlen, dbuf *hdrs)
{
	size_t val_strlen;

	val_strlen = de_strlen(val_sz);
	if(val_strlen < fieldlen) {
		dbuf_write(hdrs, (const u8*)val_sz, val_strlen);
		dbuf_write_zeroes(hdrs, fieldlen - val_strlen);
	}
	else if(val_strlen==fieldlen) {
		dbuf_write(hdrs, (const u8*)val_sz, fieldlen);
	}
	else {
		dbuf_write(hdrs, (const u8*)val_sz, fieldlen);
	}
}

static void format_and_append_ascii_octal_field(deark *c, struct tar_ctx *tctx,
	i64 val, size_t fieldlen, dbuf *hdrs)
{
	u8 buf[12];

	if(fieldlen>12) return;
	format_ascii_octal_field(c, tctx, val, buf, fieldlen);
	dbuf_write(hdrs, buf, fieldlen);
}

void de_tar_end_member_file(deark *c, dbuf *f)
{
	struct tar_ctx *tctx = (struct tar_ctx *)c->tar_data;
	i64 padded_len;
	i64 saved_pos;
	i64 mode;
	u8 typeflag = '0';
	dbuf *hdrs = NULL;

	// Write any needed padding to the main tar file.
	padded_len = de_pad_to_n(f->len, 512);
	dbuf_write_zeroes(tctx->outf, padded_len - f->len);

	// Preparations

	if(f->fi_copy && f->fi_copy->mod_time.is_valid) {
		tctx->md.modtime_unix = de_timestamp_to_unix_time(&f->fi_copy->mod_time);
	}
	else {
		if(!c->current_time.is_valid) {
			de_current_time_to_timestamp(&c->current_time);
		}
		tctx->md.modtime_unix = de_timestamp_to_unix_time(&c->current_time);
	}

	// Construct the headers, using a temporary dbuf.

	hdrs = dbuf_create_membuf(c, tctx->md.headers_size, 0);

	// "name"
	format_and_append_ascii_field(c, tctx, f->name, 100, hdrs);

	// "mode"
	dbuf_truncate(hdrs, 100);
	if(f->fi_copy && f->fi_copy->is_directory) {
		mode = 0755;
		typeflag = '5';
	}
	else if(f->fi_copy && (f->fi_copy->mode_flags&DE_MODEFLAG_EXE)) {
		mode = 0755;
	}
	else {
		mode = 0644;
	}
	format_and_append_ascii_octal_field(c, tctx, mode, 8, hdrs);

	// uid
	format_and_append_ascii_octal_field(c, tctx, 0, 8, hdrs);
	// gid
	format_and_append_ascii_octal_field(c, tctx, 0, 8, hdrs);

	// "size"
	dbuf_truncate(hdrs, 124);
	format_and_append_ascii_octal_field(c, tctx, f->len, 12, hdrs);

	// mtime
	format_and_append_ascii_octal_field(c, tctx, tctx->md.modtime_unix, 12, hdrs);

	// typeflag
	dbuf_truncate(hdrs, 156);
	dbuf_writebyte(hdrs, typeflag);

	// magic/version
	dbuf_truncate(hdrs, 257);
	dbuf_write(hdrs, (const u8*)"ustar\0" "00", 8);

	dbuf_truncate(hdrs, 265);
	format_and_append_ascii_field(c, tctx, "root", 32, hdrs); // uname
	format_and_append_ascii_field(c, tctx, "root", 32, hdrs); // gname

	// Done with main header

	dbuf_truncate(hdrs, tctx->md.headers_size);
	set_checksum_field(c, tctx, hdrs, 0);

	// Seek back and write the headers to the main tar file.
	// FIXME: This is a hack, sort of. A dbuf doesn't expect us to access its
	// fp pointer, or to mix copy_at with other 'write' functions.
	saved_pos = de_ftell(tctx->outf->fp);
	dbuf_copy_at(hdrs, 0, tctx->md.headers_size, tctx->outf, tctx->md.headers_pos);
	de_fseek(tctx->outf->fp, saved_pos, SEEK_SET);

	dbuf_close(hdrs);
}
