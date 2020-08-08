// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// LBR - uncompressed CP/M archive format
// Squeeze compressed file

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_lbr);
DE_DECLARE_MODULE(de_module_squeeze);

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

///////////////////////////////////////////////
// Squeeze - CP/M compressed file format

struct squeeze_ctx {
	u8 is_sq2;
	de_encoding input_encoding;
	struct de_stringreaderdata *fn;
	struct de_stringreaderdata *timestamp_string;
	struct de_stringreaderdata *comment;
	UI checksum_reported;
	UI checksum_calc;
	i64 cmpr_data_pos;
	struct de_timestamp timestamp;
};

static void squeeze_writelistener_cb(dbuf *f, void *userdata, const u8 *buf, i64 buf_len)
{
	struct squeeze_ctx *sqctx = (struct squeeze_ctx*)userdata;
	i64 i;

	for(i=0; i<buf_len; i++) {
		sqctx->checksum_calc += buf[i];
	}
}

static void do_sqeeze_timestamp(deark *c, struct squeeze_ctx *sqctx, i64 pos1)
{
	UI cksum_calc = 0;
	UI cksum_reported;
	i64 pos = pos1;
	i64 sig;
	i64 dt_raw, tm_raw;
	char timestamp_buf[64];

	if(c->infile->len-pos1 < 8) return;
	sig = de_getu16le_p(&pos);
	if(sig != 0xff77) return;
	dt_raw = de_getu16le_p(&pos);
	tm_raw = de_getu16le_p(&pos);
	cksum_reported = (UI)de_getu16le_p(&pos);
	cksum_calc = ((UI)sig + (UI)dt_raw + (UI)tm_raw)&0xffff;
	if(cksum_calc != cksum_reported) return; // Presumably a false positive signature

	de_dbg(c, "timestamp at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	de_dos_datetime_to_timestamp(&sqctx->timestamp, dt_raw, tm_raw);

	sqctx->timestamp.tzcode = DE_TZCODE_LOCAL;
	de_timestamp_to_string(&sqctx->timestamp, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "timestamp: %s", timestamp_buf);

	de_dbg(c, "timestamp checksum (calculated): 0x%04x", cksum_calc);
	de_dbg(c, "timestamp checksum (reported): 0x%04x", cksum_reported);
	de_dbg_indent(c, -1);
}

static void read_squeeze_checksum(deark *c, struct squeeze_ctx *sqctx, i64 pos)
{
	sqctx->checksum_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "checksum (reported): %u", (UI)sqctx->checksum_reported);
}

static int read_squeeze_filename(deark *c, struct squeeze_ctx *sqctx, i64 pos, i64 *pbytes_consumed)
{
	int retval = 0;

	sqctx->fn = dbuf_read_string(c->infile, pos, 300, 300, DE_CONVFLAG_STOP_AT_NUL,
		sqctx->input_encoding);
	if(!sqctx->fn->found_nul)goto done;
	de_dbg(c, "original filename: \"%s\"", ucstring_getpsz_d(sqctx->fn->str));
	*pbytes_consumed = sqctx->fn->bytes_consumed;
	retval = 1;

done:
	return retval;
}

static int read_squeeze_headers(deark *c, struct squeeze_ctx *sqctx, i64 pos1)
{
	i64 pos = pos1;
	int retval = 0;
	i64 bytes_consumed = 0;

	read_squeeze_checksum(c, sqctx, pos);
	pos += 2;

	if(!read_squeeze_filename(c, sqctx, pos, &bytes_consumed)) goto done;
	pos += bytes_consumed;

	sqctx->cmpr_data_pos = pos;
	retval = 1;
done:
	if(!retval) {
		de_err(c, "Malformed header");
	}
	return retval;
}

static int read_sq2_headers(deark *c, struct squeeze_ctx *sqctx, i64 pos1)
{
	i64 pos = pos1;
	i64 bytes_consumed = 0;
	u8 b;
	int retval = 0;

	if(!read_squeeze_filename(c, sqctx, pos, &bytes_consumed)) goto done;
	pos += bytes_consumed;

	sqctx->timestamp_string = dbuf_read_string(c->infile, pos, 300, 300,
		DE_CONVFLAG_STOP_AT_NUL, sqctx->input_encoding);
	if(!sqctx->timestamp_string->found_nul) goto done;
	de_dbg(c, "timestamp_string: \"%s\"", ucstring_getpsz_d(sqctx->timestamp_string->str));
	pos += sqctx->timestamp_string->bytes_consumed;

	sqctx->comment = dbuf_read_string(c->infile, pos, 300, 300,
		DE_CONVFLAG_STOP_AT_NUL, sqctx->input_encoding);
	if(!sqctx->comment->found_nul) goto done;
	de_dbg(c, "comment: \"%s\"", ucstring_getpsz_d(sqctx->comment->str));
	pos += sqctx->comment->bytes_consumed;

	b = de_getbyte_p(&pos);
	if(b != 0x1a) goto done;

	read_squeeze_checksum(c, sqctx, pos);
	pos += 2;

	pos += 4; // ?

	sqctx->cmpr_data_pos = pos;
	retval = 1;

done:
	if(!retval) {
		de_err(c, "Malformed header");
	}
	return retval;
}

static void de_run_squeeze(deark *c, de_module_params *mparams)
{
	i64 pos = 0;
	i64 n;
	struct squeeze_ctx *sqctx = NULL;
	de_finfo *fi = NULL;
	dbuf *outf_tmp = NULL;
	dbuf *outf_final = NULL;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	sqctx = de_malloc(c, sizeof(struct squeeze_ctx));
	sqctx->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);

	n = de_getu16le_p(&pos);
	if(n==0xff76) {
		de_declare_fmt(c, "Squeezed");
	}
	else if(n==0xfffa) {
		de_declare_fmt(c, "Squeeze v2 (SQ2)");
		sqctx->is_sq2 = 1;
	}
	else {
		de_dbg(c, "Not a Squeezed file");
		goto done;
	}

	if(sqctx->is_sq2) {
		if(!read_sq2_headers(c, sqctx, pos)) goto done;
	}
	else {
		if(!read_squeeze_headers(c, sqctx, pos)) goto done;
	}

	pos = sqctx->cmpr_data_pos;

	fi = de_finfo_create(c);
	de_finfo_set_name_from_ucstring(c, fi, sqctx->fn->str, 0);
	fi->original_filename_flag = 1;

	de_dbg(c, "squeeze-compressed data at %"I64_FMT, pos);

	// We have to decompress the file before we can find the timestamp. That's
	// why we decompress to a membuf.
	outf_tmp = dbuf_create_membuf(c, 0, 0);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = pos;
	dcmpri.len = c->infile->len - pos;
	dcmpro.f = outf_tmp;

	dbuf_set_writelistener(outf_tmp, squeeze_writelistener_cb, (void*)sqctx);

	de_dfilter_decompress_two_layer(c, dfilter_huff_squeeze_codec, NULL,
		dfilter_rle90_codec, NULL, &dcmpri, &dcmpro, &dres);

	if(dres.bytes_consumed_valid) {
		de_dbg(c, "compressed data size: %"I64_FMT", ends at %"I64_FMT, dres.bytes_consumed,
			dcmpri.pos+dres.bytes_consumed);

		do_sqeeze_timestamp(c, sqctx, dcmpri.pos+dres.bytes_consumed);
		if(sqctx->timestamp.is_valid) {
			fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = sqctx->timestamp;
		}
	}

	outf_final = dbuf_create_output_file(c, NULL, fi, 0);
	dbuf_copy(outf_tmp, 0, outf_tmp->len, outf_final);

	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	sqctx->checksum_calc &= 0xffff;
	de_dbg(c, "checksum (calculated): %u", (UI)sqctx->checksum_calc);
	if(sqctx->checksum_calc != sqctx->checksum_reported) {
		de_err(c, "Checksum error. Decompression probably failed.");
		goto done;
	}

done:
	if(sqctx) {
		de_destroy_stringreaderdata(c, sqctx->fn);
		de_destroy_stringreaderdata(c, sqctx->timestamp_string);
		de_destroy_stringreaderdata(c, sqctx->comment);
		de_free(c, sqctx);
	}
	dbuf_close(outf_final);
	dbuf_close(outf_tmp);
	de_finfo_destroy(c, fi);
}

static int de_identify_squeeze(deark *c)
{
	i64 id;

	id = de_getu16le(0);
	if(id==0xff76) return 70;
	if(id==0xfffa) return 25; // SQ2
	return 0;
}

void de_module_squeeze(deark *c, struct deark_module_info *mi)
{
	mi->id = "squeeze";
	mi->desc = "Squeeze (CP/M)";
	mi->run_fn = de_run_squeeze;
	mi->identify_fn = de_identify_squeeze;
}
