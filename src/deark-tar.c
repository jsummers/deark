// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// TAR format output

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"

struct timestamp_data {
	struct de_timestamp timestamp;
	i64 timestamp_unix; // Same time as .timestamp, for convenience
	u8 need_exthdr;
	char exthdr_sz[32];
};

struct tar_md {
	u8 is_dir;
	u8 has_exthdr;
	u8 need_exthdr_size;
	u8 need_exthdr_path;
	size_t namelen;
	i64 headers_pos;
	i64 headers_size;
	i64 exthdr_num_data_blocks;
	i64 extdata_nbytes_needed;
	i64 extdata_nbytes_used;
	char *filename;
	struct timestamp_data tsdata[DE_TIMESTAMPIDX_COUNT];
};

struct tar_ctx {
	const char *tar_filename;
	dbuf *outf;
	i64 checksum_calc; // for temporary use

	// Data associated with current member file
	struct tar_md *md;
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

static void destroy_md(deark *c, struct tar_md *md)
{
	if(!md) return;
	de_free(c, md->filename);
	de_free(c, md);
}

void de_tar_close_file(deark *c)
{
	struct tar_ctx *tctx = (struct tar_ctx *)c->tar_data;

	if(!tctx) return;
	if(tctx->outf) {
		dbuf_write_zeroes(tctx->outf, 512*2);
		dbuf_close(tctx->outf);
	}
	destroy_md(c, tctx->md);
	de_free(c, tctx);
	c->tar_data = NULL;
}

static void prepare_timestamp_exthdr(deark *c, struct tar_md *md, int tsidx)
{
	i64 unix_time;
	i64 subsec = 0;
	int is_high_prec = 0;
	struct timestamp_data *tsd = &md->tsdata[tsidx];

	if(!tsd->timestamp.is_valid) return;

	unix_time = tsd->timestamp_unix;

	if(unix_time>=0 && tsd->timestamp.precision>DE_TSPREC_1SEC) {
		subsec = de_timestamp_get_subsec(&tsd->timestamp);
		if(subsec!=0) is_high_prec = 1;
	}

	if(tsidx!=DE_TIMESTAMPIDX_MODIFY || is_high_prec || unix_time<0 || unix_time>0x1ffffffffLL) {
		tsd->need_exthdr = 1;
	}
	else {
		return;
	}

	if(is_high_prec) {
		de_snprintf(tsd->exthdr_sz, sizeof(tsd->exthdr_sz),
			"%"I64_FMT".%07"I64_FMT, unix_time, subsec);
	}
	else {
		de_snprintf(tsd->exthdr_sz, sizeof(tsd->exthdr_sz),
			"%"I64_FMT, unix_time);
	}

	// Max length for this item is around 29, so we allow 2 bytes for the
	// length field.
	// E.g. "28 mtime=1222333444.5555555\n"
	md->extdata_nbytes_needed += 2 + 1 + 5 + 1 + (i64)de_strlen(tsd->exthdr_sz) + 1;
}

// f is type DBUF_TYPE_ODBUF, in the process of being created.
// We are responsible for setting f->parent_dbuf and
// f->offset_into_parent_dbuf.
void de_tar_start_member_file(deark *c, dbuf *f)
{
	struct tar_ctx *tctx = NULL;
	struct tar_md *md = NULL;
	int tsidx;

	if(!c->tar_data) {
		de_tar_create_file(c);
	}
	tctx = (struct tar_ctx *)c->tar_data;
	if(!tctx) return;
	destroy_md(c, tctx->md);
	tctx->md = de_malloc(c, sizeof(struct tar_md));
	md = tctx->md;

	f->parent_dbuf = tctx->outf;

	md->headers_pos = tctx->outf->len;

	if(c->preserve_file_times_archives && f->fi_copy) {
		for(tsidx=0; tsidx<DE_TIMESTAMPIDX_COUNT; tsidx++) {
			//if(tsidx != DE_TIMESTAMPIDX_MODIFY) continue;

			if(f->fi_copy->timestamp[tsidx].is_valid) {
				md->tsdata[tsidx].timestamp = f->fi_copy->timestamp[tsidx];
			}
			else if(tsidx == DE_TIMESTAMPIDX_MODIFY) {
				// Special handling if we don't have a mod time.
				if(c->reproducible_output) {
					de_get_reproducible_timestamp(c, &md->tsdata[tsidx].timestamp);
				}
				else {
					de_cached_current_time_to_timestamp(c, &md->tsdata[tsidx].timestamp);
					// Although c->current_time is probably high precision, we treat it as
					// low precision, so as not to write an "mtime" extended header.
					// TODO: If we write "mtime" for some other reason, it can be high prec.
					md->tsdata[tsidx].timestamp.precision = DE_TSPREC_1SEC;
				}
			}
			else {
				// Unavailable timestamp that isn't the mod time.
				continue;
			}

			md->tsdata[tsidx].timestamp_unix = de_timestamp_to_unix_time(&md->tsdata[tsidx].timestamp);
		}
	}

	if(f->fi_copy && f->fi_copy->is_directory) {
		md->is_dir = 1;
	}

	md->namelen = de_strlen(f->name);
	if(md->is_dir) {
		// Append a '/' to directory names
		md->filename = de_malloc(c, (i64)md->namelen+2);
		de_snprintf(md->filename, md->namelen+2, "%s/", f->name);
		md->namelen = de_strlen(md->filename);
	}
	else {
		md->filename = de_strdup(c, f->name);
	}

	if(md->namelen>100) {
		md->need_exthdr_path = 1;
	}
	else if(!de_is_ascii((const u8*)md->filename, md->namelen)) {
		md->need_exthdr_path = 1;
	}

	md->extdata_nbytes_needed += 23; // For "size"; this is enough for 10TB

	if(md->need_exthdr_path) {
		// Likely an overestimate: up to 6 bytes for the item size,
		// 4 for the "path" string, 3 for field separators.
		md->extdata_nbytes_needed += (i64)md->namelen + 13;
	}

	prepare_timestamp_exthdr(c, md, DE_TIMESTAMPIDX_MODIFY);
	prepare_timestamp_exthdr(c, md, DE_TIMESTAMPIDX_ACCESS);
	prepare_timestamp_exthdr(c, md, DE_TIMESTAMPIDX_ATTRCHANGE);
	prepare_timestamp_exthdr(c, md, DE_TIMESTAMPIDX_CREATE);

	if(md->extdata_nbytes_needed>0) {
		md->has_exthdr = 1;
	}

	if(md->has_exthdr) {
		md->exthdr_num_data_blocks = (md->extdata_nbytes_needed+511)/512;
		md->headers_size = (1 + md->exthdr_num_data_blocks + 1) * 512;
	}
	else {
		md->exthdr_num_data_blocks = 0;
		md->headers_size = 512;
	}

	// Reserve space for the tar headers. We won't know the member file size
	// until it has been completely written, so we can't write the headers
	// yet. Instead we'll write them to headers_tmpdbuf, and seek back later
	// and patch them into the main tar file.
	dbuf_write_zeroes(tctx->outf, md->headers_size);

	f->offset_into_parent_dbuf = tctx->outf->len;
}

// TODO: Maybe support "base-256" format.
static int format_ascii_octal_field(deark *c, struct tar_ctx *tctx,
	i64 val, u8 *buf2, size_t buf2len)
{
	char buf1[32]; // The largest field we need to support is 12 bytes
	size_t k;
	size_t len_in_octal;

	de_zeromem(buf2, buf2len);
	if(buf2len>12) return 0;
	if(val<0) val = 0;

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
	struct tar_ctx *tctx = (struct tar_ctx*)brctx->userdata;
	i64 i;

	for(i=0; i<buf_len; i++) {
		if((brctx->offset+i) >=148 && (brctx->offset+i)<156)
			tctx->checksum_calc += 32; // (The checksum field itself)
		else
			tctx->checksum_calc += (i64)buf[i];
	}

	return 1;
}

// Set the checksum field for the header starting at 'pos'.
static void set_checksum_field(deark *c, struct tar_ctx *tctx,
	dbuf *hdr)
{
	u8 buf[8];

	tctx->checksum_calc = 0;
	dbuf_buffered_read(hdr, 0, 512, cksum_cbfn, (void*)tctx);

	format_ascii_octal_field(c, tctx, tctx->checksum_calc, buf, 7);
	buf[6] = 0x00;
	buf[7] = 0x20;
	dbuf_write_at(hdr, 148, buf, 8);
}

static void format_and_write_ascii_field(deark *c, struct tar_ctx *tctx,
	const char *val_sz, size_t fieldlen, dbuf *hdrs, i64 fieldpos)
{
	size_t val_strlen;

	val_strlen = de_strlen(val_sz);
	if(val_strlen < fieldlen) {
		dbuf_write_at(hdrs, fieldpos, (const u8*)val_sz, val_strlen);
		// (padding bytes will remain at 0)
	}
	else if(val_strlen==fieldlen) {
		dbuf_write_at(hdrs, fieldpos, (const u8*)val_sz, fieldlen);
	}
	else {
		dbuf_write_at(hdrs, fieldpos, (const u8*)val_sz, fieldlen);
	}
}

static void format_and_write_ascii_octal_field(deark *c, struct tar_ctx *tctx,
	i64 val, size_t fieldlen, dbuf *hdrs, i64 fieldpos)
{
	u8 buf[12];

	if(fieldlen>12) return;
	format_ascii_octal_field(c, tctx, val, buf, fieldlen);
	dbuf_write_at(hdrs, fieldpos, buf, fieldlen);
}

// Set fields common to both the main header, and the POSIX extended (Pax)
// header.
static void set_common_header_fields(deark *c, struct tar_ctx *tctx,
	dbuf *hdr)
{
	struct tar_md *md = tctx->md;

	// uid
	format_and_write_ascii_octal_field(c, tctx, 0, 8, hdr, 108);
	// gid
	format_and_write_ascii_octal_field(c, tctx, 0, 8, hdr, 116);
	// mtime
	format_and_write_ascii_octal_field(c, tctx, md->tsdata[DE_TIMESTAMPIDX_MODIFY].timestamp_unix, 12, hdr, 136);
	// magic/version
	dbuf_write_at(hdr, 257, (const u8*)"ustar\0" "00", 8);
	format_and_write_ascii_field(c, tctx, "root", 32, hdr, 265); // uname
	format_and_write_ascii_field(c, tctx, "root", 32, hdr, 297); // gname
}

static void make_main_header(deark *c, struct tar_ctx *tctx,
	dbuf *f, dbuf *mainhdr)
{
	struct tar_md *md = tctx->md;
	i64 mode;
	u8 typeflag = '0';

	if(md->is_dir) {
		mode = 0755;
		typeflag = '5';
	}
	else if(f->fi_copy && (f->fi_copy->mode_flags&DE_MODEFLAG_EXE)) {
		mode = 0755;
	}
	else {
		mode = 0644;
	}

	set_common_header_fields(c, tctx, mainhdr);

	// "name"
	format_and_write_ascii_field(c, tctx, md->filename, 100, mainhdr, 0);

	// "mode"
	format_and_write_ascii_octal_field(c, tctx, mode, 8, mainhdr, 100);

	// "size"
	format_and_write_ascii_octal_field(c, tctx, f->len, 12, mainhdr, 124);

	// typeflag
	dbuf_writebyte_at(mainhdr, 156, typeflag);

	// Done populating main header, now set the checksum

	dbuf_truncate(mainhdr, 512);
	set_checksum_field(c, tctx, mainhdr);
}

// *ppos is the current offset into extdata. It will be updated.
static void add_exthdr_item(deark *c, struct tar_ctx *tctx,
	dbuf *extdata, const char *name, const char *val, i64 *ppos)
{
	i64 len1;
	i64 item_len = 0;
	char *tmps = NULL;

	len1 = (i64)de_strlen(name) + (i64)de_strlen(val) + 3;
	// This size of the size field depends on itself. Ugh.
	if(len1<=8) item_len = len1+1;
	else if(len1<=97) item_len = len1+2;
	else if(len1<=996) item_len = len1+3;
	else if(len1<=9995) item_len = len1+4;
	else if(len1<=99994) item_len = len1+5;
	else if(len1<=999993) item_len = len1+6;
	else { // Error
		(*ppos)++;
		goto done;
	}

	tmps = de_malloc(c, item_len+1);
	de_snprintf(tmps, (size_t)(item_len+1), "%"I64_FMT" %s=%s\n", item_len, name, val);
	dbuf_write_at(extdata, *ppos, (const u8*)tmps, item_len);
	(*ppos) += item_len;

done:
	de_free(c, tmps);
}

static void make_exthdrs(deark *c, struct tar_ctx *tctx,
	dbuf *f, dbuf *exthdr, dbuf *extdata)
{
	struct tar_md *md = tctx->md;
	i64 extdata_len = 0;
	char namebuf[101];
	char buf[80];

	set_common_header_fields(c, tctx, exthdr);

	// "name"
	// This pseudo-filename will be ignored by any decent untar program.
	// The template used here is similar to what bsdtar does.
	// (Using f->name here instead of md->filename, because we don't
	// want directory names to have a '/' appended.)
	de_snprintf(namebuf, sizeof(namebuf), "PaxHeader/%s", f->name);
	format_and_write_ascii_field(c, tctx, namebuf, 100, exthdr, 0);

	// "mode"
	format_and_write_ascii_octal_field(c, tctx, 0644, 8, exthdr, 100);

	// typeflag
	dbuf_writebyte_at(exthdr, 156, 'x');

	// Extended data

	if(md->need_exthdr_size) {
		de_snprintf(buf, sizeof(buf), "%"I64_FMT, f->len);
		add_exthdr_item(c, tctx, extdata, "size", buf, &extdata_len);
	}

	if(md->need_exthdr_path) {
		add_exthdr_item(c, tctx, extdata, "path", md->filename, &extdata_len);
	}

	if(md->tsdata[DE_TIMESTAMPIDX_MODIFY].need_exthdr) {
		add_exthdr_item(c, tctx, extdata, "mtime", md->tsdata[DE_TIMESTAMPIDX_MODIFY].exthdr_sz, &extdata_len);
	}
	if(md->tsdata[DE_TIMESTAMPIDX_ACCESS].need_exthdr) {
		add_exthdr_item(c, tctx, extdata, "atime", md->tsdata[DE_TIMESTAMPIDX_ACCESS].exthdr_sz, &extdata_len);
	}
	if(md->tsdata[DE_TIMESTAMPIDX_ATTRCHANGE].need_exthdr) {
		add_exthdr_item(c, tctx, extdata, "ctime", md->tsdata[DE_TIMESTAMPIDX_ATTRCHANGE].exthdr_sz, &extdata_len);
	}
	if(md->tsdata[DE_TIMESTAMPIDX_CREATE].need_exthdr) {
		add_exthdr_item(c, tctx, extdata, "LIBARCHIVE.creationtime", md->tsdata[DE_TIMESTAMPIDX_CREATE].exthdr_sz, &extdata_len);
	}

	// We have to use exactly the number of exthdr data blocks that we
	// precalculated, no more and no fewer. But it is possible that we
	// overestimated. If so, we have to pad the data somehow, and using
	// empty "comment" items is one way to do that.
	while(extdata_len < (512*md->exthdr_num_data_blocks - 511)) {
		add_exthdr_item(c, tctx, extdata, "comment", "", &extdata_len);
	}
	dbuf_truncate(extdata, 512*md->exthdr_num_data_blocks);

	// "size"
	format_and_write_ascii_octal_field(c, tctx, extdata_len, 12, exthdr, 124);

	dbuf_truncate(exthdr, 512);
	set_checksum_field(c, tctx, exthdr);
}

void de_tar_end_member_file(deark *c, dbuf *f)
{
	struct tar_ctx *tctx = (struct tar_ctx *)c->tar_data;
	struct tar_md *md = tctx->md;
	i64 padded_len;
	i64 saved_pos;
	i64 writepos;
	dbuf *mainhdr = NULL;
	dbuf *exthdr = NULL;
	dbuf *extdata = NULL;

	// Write any needed padding to the main tar file.
	padded_len = de_pad_to_n(f->len, 512);
	dbuf_write_zeroes(tctx->outf, padded_len - f->len);

	// Construct the headers, using temporary dbufs

	// Main header
	mainhdr = dbuf_create_membuf(c, 512, 0);
	make_main_header(c, tctx, f, mainhdr);

	if(md->has_exthdr) {
		// Extended header & data
		exthdr = dbuf_create_membuf(c, 512, 0);
		extdata = dbuf_create_membuf(c, 512*md->exthdr_num_data_blocks, 0);
		md->need_exthdr_size = (f->len > 0x1FFFFFFFFLL)?1:0;
		make_exthdrs(c, tctx, f, exthdr, extdata);
	}

	// Seek back and write the headers to the main tar file.
	// FIXME: This is a hack, sort of. A dbuf doesn't expect us to access its
	// fp pointer, or to mix copy_at with other 'write' functions.
	saved_pos = de_ftell(tctx->outf->fp);
	writepos = md->headers_pos;
	if(md->has_exthdr && exthdr && extdata) {
		dbuf_copy_at(exthdr, 0, 512, tctx->outf, writepos);
		writepos += 512;
		dbuf_copy_at(extdata, 0, 512*md->exthdr_num_data_blocks, tctx->outf, writepos);
		writepos += 512*md->exthdr_num_data_blocks;
	}
	dbuf_copy_at(mainhdr, 0, 512, tctx->outf, writepos);
	de_fseek(tctx->outf->fp, saved_pos, SEEK_SET);

	dbuf_close(mainhdr);
	dbuf_close(exthdr);
	dbuf_close(extdata);

	destroy_md(c, tctx->md);
	tctx->md = NULL;
}
