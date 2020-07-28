// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// LBR - uncompressed CP/M archive format

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_lbr);

#define LBR_DIRENT_SIZE 32
#define LBR_SECTOR_SIZE 128

struct member_data {
	int is_dir;
	u8 status;
	u8 pad_count;
	u32 crc_reported;
	u32 crc_calc;
	i64 pos_in_sectors;
	i64 pos_in_bytes;
	i64 len_in_sectors;
	i64 len_in_bytes_withpadding;
	i64 len_in_bytes_nopadding;
	de_ucstring *fn;
	struct de_timestamp create_timestamp;
	struct de_timestamp change_timestamp;
};

typedef struct localctx_struct {
	de_encoding input_encoding;
	i64 dir_len_in_bytes;
	struct de_crcobj *crco;
} lctx;

static void our_writelistener_cb(dbuf *f, void *userdata, const u8 *buf, i64 buf_len)
{
	struct de_crcobj *crco = (struct de_crcobj*)userdata;
	de_crcobj_addbuf(crco, buf, buf_len);
}

static void do_extract_member(deark *c, lctx *d, struct member_data *md)
{
	de_finfo *fi = NULL;
	dbuf *outf = NULL;

	fi = de_finfo_create(c);
	if(md->is_dir) {
		fi->is_directory = 1;
		fi->is_root_dir = 1;
	}
	else {
		de_finfo_set_name_from_ucstring(c, fi, md->fn, 0);
		fi->original_filename_flag = 1;
	}

	if(md->create_timestamp.is_valid) {
		fi->timestamp[DE_TIMESTAMPIDX_CREATE] = md->create_timestamp;
	}
	if(md->change_timestamp.is_valid) {
		fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = md->change_timestamp;
	}

	outf = dbuf_create_output_file(c, NULL, fi, 0x0);

	de_crcobj_reset(d->crco);
	if(md->is_dir) {
		de_crcobj_addslice(d->crco, c->infile, md->pos_in_bytes, 16);
		de_crcobj_addbyte(d->crco, 0); // The 2-byte CRC field...
		de_crcobj_addbyte(d->crco, 0);
		de_crcobj_addslice(d->crco, c->infile, md->pos_in_bytes+18, md->len_in_bytes_withpadding-18);
	}
	else {
		dbuf_set_writelistener(outf, our_writelistener_cb, (void*)d->crco);
		dbuf_copy(c->infile, md->pos_in_bytes, md->len_in_bytes_nopadding, outf);
		// CRC calculation includes padding bytes:
		de_crcobj_addslice(d->crco, c->infile,
			md->pos_in_bytes + md->len_in_bytes_nopadding,
			md->len_in_bytes_withpadding - md->len_in_bytes_nopadding);
	}
	md->crc_calc = de_crcobj_getval(d->crco);
	de_dbg(c, "crc (calculated): 0x%04x", (UI)md->crc_calc);

	de_finfo_destroy(c, fi);
	dbuf_close(outf);
}

static void read_8_3_filename(deark *c, lctx *d, struct member_data *md, i64 pos)
{
	de_ucstring *ext = NULL;

	dbuf_read_to_ucstring(c->infile, pos, 8, md->fn, 0, d->input_encoding);
	ucstring_strip_trailing_spaces(md->fn);
	if(md->fn->len==0) {
		ucstring_append_char(md->fn, '_');
	}

	ext = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos+8, 3, ext, 0, d->input_encoding);
	ucstring_strip_trailing_spaces(ext);
	if(ext->len>0) {
		ucstring_append_char(md->fn, '.');
		ucstring_append_ucstring(md->fn, ext);
	}

	ucstring_destroy(ext);
}

static void handle_timestamp(deark *c, lctx *d, i64 date_raw, i64 time_raw,
	struct de_timestamp *ts, const char *name)
{
	i64 ut;
	char timestamp_buf[64];

	if(date_raw==0) {
		de_dbg(c, "%s: [not set]", name);
		return;
	}

	// Day 0 is Dec 31, 1977 (or it would be, if 0 weren't reserved).
	// Difference from Unix time (Jan 1, 1970) =
	//  365 days in 1970, 1971, 1973, 1974, 1975
	//  + 366 days in 1972, 1976
	//  + 364 days in 1977.
	ut = 86400 * (date_raw + (365*5 + 366*2 + 364));

	// Time of day is in DOS format.
	ut += 3600*(time_raw>>11); // hours
	ut += 60*(time_raw&0x07e0)>>5; // minutes
	ut += 2*(time_raw&0x001f); // seconds
	de_unix_time_to_timestamp(ut, ts, 0);
	de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %s", name, timestamp_buf);
}

static void on_bad_dir(deark *c)
{
	de_err(c, "Bad directory. This is probably not an LBR file.");
}

// Returns nonzero if we can continue.
// if is_dir, sets d->dir_len_in_bytes.
static int do_entry(deark *c, lctx *d, i64 pos1, int is_dir)
{
	int retval = 0;
	int saved_indent_level;
	struct member_data *md = NULL;
	i64 crdate, chdate, crtime, chtime;

	de_dbg_indent_save(c, &saved_indent_level);
	md = de_malloc(c, sizeof(struct member_data));
	md->is_dir = is_dir;

	de_dbg(c, "%s entry at %"I64_FMT, (md->is_dir?"dir":"file"), pos1);
	de_dbg_indent(c, 1);

	md->status = de_getbyte(pos1);
	de_dbg(c, "status: 0x%02x", (UI)md->status);
	if(md->is_dir && md->status!=0x00) {
		on_bad_dir(c);
		goto done;
	}
	if(md->status==0xff) { // unused entry - marks end of directory
		goto done;
	}
	if(md->status!=0x00) { // deleted entry (should be 0xfe)
		de_dbg(c, "[deleted]");
		retval = 1;
		goto done;
	}

	md->fn = ucstring_create(c);
	if(!md->is_dir) {
		read_8_3_filename(c, d, md, pos1+1);
		de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->fn));
	}

	md->pos_in_sectors = de_getu16le(pos1+12);
	md->pos_in_bytes = md->pos_in_sectors * LBR_SECTOR_SIZE;
	de_dbg(c, "data offset: %"I64_FMT" (sector %"I64_FMT")", md->pos_in_bytes, md->pos_in_sectors);
	if(md->is_dir && md->pos_in_bytes!=pos1) {
		on_bad_dir(c);
		goto done;
	}

	md->len_in_sectors = de_getu16le(pos1+14);
	de_dbg(c, "length in sectors: %"I64_FMT, md->len_in_sectors);

	md->crc_reported = (u32)de_getu16le(pos1+16);
	de_dbg(c, "crc (reported): 0x%04x", (UI)md->crc_reported);

	// 18-25: timestamps - TODO
	crdate = de_getu16le(pos1+18);
	chdate = de_getu16le(pos1+20);
	crtime = de_getu16le(pos1+22);
	chtime = de_getu16le(pos1+24);
	handle_timestamp(c, d, crdate, crtime, &md->create_timestamp, "creation time");
	handle_timestamp(c, d, chdate, chtime, &md->change_timestamp, "last changed time");

	md->pad_count = de_getbyte(pos1+26);
	de_dbg(c, "pad count: %u", (UI)md->pad_count);
	if(md->pad_count>=LBR_SECTOR_SIZE || md->len_in_sectors<1) {
		md->pad_count = 0;
	}

	md->len_in_bytes_withpadding = md->len_in_sectors*LBR_SECTOR_SIZE;
	md->len_in_bytes_nopadding = md->len_in_bytes_withpadding - (i64)md->pad_count;
	de_dbg(c, "length in bytes: %"I64_FMT, md->len_in_bytes_nopadding);

	if(md->pos_in_bytes + md->len_in_bytes_nopadding > c->infile->len) {
		de_err(c, "Unexpected end of file");
		if(!md->is_dir) {
			retval = 1;
		}
		goto done;
	}

	if(md->is_dir) {
		d->dir_len_in_bytes = md->len_in_bytes_nopadding;
	}
	retval = 1;

	do_extract_member(c, d, md);

done:
	if(md) {
		ucstring_destroy(md->fn);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_lbr(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos = 0;

	d = de_malloc(c, sizeof(lctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_ASCII);

	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_CCITT);

	// Read directory
	if(!do_entry(c, d, pos, 1)) goto done;
	pos += LBR_DIRENT_SIZE;

	// Read member files
	while(pos+LBR_DIRENT_SIZE <= c->infile->len &&
		pos+LBR_DIRENT_SIZE <= d->dir_len_in_bytes)
	{
		if(!do_entry(c, d, pos, 0)) goto done;
		pos += LBR_DIRENT_SIZE;
	}

done:
	if(d) {
		de_crcobj_destroy(d->crco);
		de_free(c, d);
	}
}

static int de_identify_lbr(deark *c)
{
	// TODO: Better detection is possible
	if(!dbuf_memcmp(c->infile, 0, "\x00\x20\x20\x20\x20\x20\x20\x20\x20"
		"\x20\x20\x20\x00\x00", 14))
		return 100;
	return 0;
}

void de_module_lbr(deark *c, struct deark_module_info *mi)
{
	mi->id = "lbr";
	mi->desc = "LBR archive";
	mi->run_fn = de_run_lbr;
	mi->identify_fn = de_identify_lbr;
}
