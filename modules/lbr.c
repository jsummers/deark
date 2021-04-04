// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// LBR - uncompressed CP/M archive format
// Squeeze compressed file
// Crunch v1 compressed file
// ZSQ compressed file
// LZWCOM compressed file

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_lbr);
DE_DECLARE_MODULE(de_module_squeeze);
DE_DECLARE_MODULE(de_module_crunch);
DE_DECLARE_MODULE(de_module_crlzh);
DE_DECLARE_MODULE(de_module_zsq);
DE_DECLARE_MODULE(de_module_lzwcom);

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
		de_crcobj_addzeroes(d->crco, 2); // The 2-byte CRC field
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

// For Crunch/CRLZH(/Squeeze?) filename fields
struct crcr_filename_data {
	de_ucstring *fn;
	de_ucstring *comment;
	i64 size;
};

static int crcr_read_filename_etc(deark *c, i64 pos1, struct crcr_filename_data *fnd)
{
	int retval = 0;
	i64 pos = pos1;
	enum crcrfnstate {
		CRCRFNST_NEUTRAL, CRCRFNST_FILENAME, CRCRFNST_COMMENT, CRCRFNST_DATE
	};
	enum crcrfnstate state = CRCRFNST_FILENAME;
	int found_dot = 0;
	int extension_char_count = 0;

	// Note: Only ASCII can really be supported, because the characters are 7-bit.
	// Normally, we'd use ucstring_append_bytes_ex() for something like this, but
	// it's pointless here.
	fnd->fn = ucstring_create(c);

	while(1) {
		u8 b;

		// Note: CFX limits this entire field to about 80 bytes.
		if(pos-pos1 > 300) goto done;
		if(pos >= c->infile->len) goto done;

		b = de_getbyte_p(&pos) & 0x7f;
		if(b==0) {
			break;
		}

		if(b==0x01) {
			state = CRCRFNST_DATE; // TODO: Figure this field out
		}
		else if(state==CRCRFNST_FILENAME && b=='[') {
			state = CRCRFNST_COMMENT;
		}
		else if(state==CRCRFNST_FILENAME && extension_char_count>=3) {
			state = CRCRFNST_NEUTRAL;
		}
		else if(state==CRCRFNST_FILENAME) {
			if(found_dot) {
				extension_char_count++;
			}
			else {
				if(b=='.') found_dot = 1;
			}
			ucstring_append_char(fnd->fn, (de_rune)b);
		}
		else if(state==CRCRFNST_COMMENT && b==']') {
			state = CRCRFNST_NEUTRAL;
		}
		else if(state==CRCRFNST_COMMENT) {
			if(!fnd->comment) {
				fnd->comment = ucstring_create(c);
			}
			ucstring_append_char(fnd->comment, (de_rune)b);
		}
	}

	ucstring_strip_trailing_spaces(fnd->fn);
	fnd->size = pos - pos1;
	retval = 1;
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(fnd->fn));
	if(fnd->comment) {
		de_dbg(c, "comment: \"%s\"", ucstring_getpsz_d(fnd->comment));
	}

done:
	return retval;
}

static void crcr_filename_data_freecontents(deark *c, struct crcr_filename_data *fnd)
{
	ucstring_destroy(fnd->fn);
	ucstring_destroy(fnd->comment);
}

struct squeeze_ctx {
	u8 is_sq2;
	de_encoding input_encoding;
	struct crcr_filename_data fnd;
	struct de_stringreaderdata *sq2_timestamp_string;
	struct de_stringreaderdata *sq2_comment;
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

static int read_squeeze_headers(deark *c, struct squeeze_ctx *sqctx, i64 pos1)
{
	i64 pos = pos1;
	int retval = 0;

	read_squeeze_checksum(c, sqctx, pos);
	pos += 2;

	// I don't know the correct way to interpret the Squeeze filename field, if
	// there even is such a way.
	// Some Unsqueeze utilities accept it as-is, some truncate it after the third
	// filename extension byte, some interpret it the same as Crunch format
	// (including ignoring the high bit of every byte, for some reason).
	// Doing it the Crunch way is probably safe.
	if(!crcr_read_filename_etc(c, pos, &sqctx->fnd)) goto done;
	pos += sqctx->fnd.size;

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
	u8 b;
	int retval = 0;

	if(!crcr_read_filename_etc(c, pos, &sqctx->fnd)) goto done;
	pos += sqctx->fnd.size;

	sqctx->sq2_timestamp_string = dbuf_read_string(c->infile, pos, 300, 300,
		DE_CONVFLAG_STOP_AT_NUL, sqctx->input_encoding);
	if(!sqctx->sq2_timestamp_string->found_nul) goto done;
	de_dbg(c, "timestamp_string: \"%s\"", ucstring_getpsz_d(sqctx->sq2_timestamp_string->str));
	pos += sqctx->sq2_timestamp_string->bytes_consumed;

	sqctx->sq2_comment = dbuf_read_string(c->infile, pos, 300, 300,
		DE_CONVFLAG_STOP_AT_NUL, sqctx->input_encoding);
	if(!sqctx->sq2_comment->found_nul) goto done;
	de_dbg(c, "comment: \"%s\"", ucstring_getpsz_d(sqctx->sq2_comment->str));
	pos += sqctx->sq2_comment->bytes_consumed;

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
	int saved_indent_level;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	struct de_dcmpr_two_layer_params tlp;

	de_dbg_indent_save(c, &saved_indent_level);
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
	de_finfo_set_name_from_ucstring(c, fi, sqctx->fnd.fn, 0);
	fi->original_filename_flag = 1;

	de_dbg(c, "squeeze-compressed data at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	// We have to decompress the file before we can find the timestamp. That's
	// why we decompress to a membuf.
	outf_tmp = dbuf_create_membuf(c, 0, 0);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = pos;
	dcmpri.len = c->infile->len - pos;
	dcmpro.f = outf_tmp;

	dbuf_set_writelistener(outf_tmp, squeeze_writelistener_cb, (void*)sqctx);

	de_zeromem(&tlp, sizeof(struct de_dcmpr_two_layer_params));
	tlp.codec1_type1 = fmtutil_huff_squeeze_codectype1;
	tlp.codec2 = dfilter_rle90_codec;
	tlp.dcmpri = &dcmpri;
	tlp.dcmpro = &dcmpro;
	tlp.dres = &dres;
	de_dfilter_decompress_two_layer(c, &tlp);

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
		crcr_filename_data_freecontents(c, &sqctx->fnd);
		de_destroy_stringreaderdata(c, sqctx->sq2_timestamp_string);
		de_destroy_stringreaderdata(c, sqctx->sq2_comment);
		de_free(c, sqctx);
	}
	dbuf_close(outf_final);
	dbuf_close(outf_tmp);
	de_finfo_destroy(c, fi);
	de_dbg_indent_restore(c, saved_indent_level);
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

///////////////////////////////////////////////
// Crunch - CP/M compressed file format

struct crunch_ctx {
	struct crcr_filename_data fnd;
	u8 cksum_type;
	UI checksum_reported;
	UI checksum_calc;
};

static void crunch_writelistener_cb(dbuf *f, void *userdata, const u8 *buf, i64 buf_len)
{
	struct crunch_ctx *crunchctx = (struct crunch_ctx*)userdata;
	i64 i;

	for(i=0; i<buf_len; i++) {
		crunchctx->checksum_calc += buf[i];
	}
}

static void decompress_crunch_v1(deark *c, struct crunch_ctx *crunchctx, i64 pos1)
{
	de_finfo *fi = NULL;
	dbuf *outf = NULL;
	i64 pos = pos1;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	struct de_lzw_params delzwp;
	struct de_dcmpr_two_layer_params tlp;

	de_dbg_indent(c, 1);
	fi = de_finfo_create(c);
	de_finfo_set_name_from_ucstring(c, fi, crunchctx->fnd.fn, 0);
	fi->original_filename_flag = 1;

	outf = dbuf_create_output_file(c, NULL, fi, 0x0);
	dbuf_set_writelistener(outf, crunch_writelistener_cb, (void*)crunchctx);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = pos;
	dcmpri.len = c->infile->len - pos;
	dcmpro.f = outf;

	de_zeromem(&delzwp, sizeof(struct de_lzw_params));
	delzwp.fmt = DE_LZWFMT_ARC5;
	delzwp.arc5_has_stop_code = 1;

	de_zeromem(&tlp, sizeof(struct de_dcmpr_two_layer_params));
	tlp.codec1_pushable = dfilter_lzw_codec;
	tlp.codec1_private_params = (void*)&delzwp;
	tlp.codec2 = dfilter_rle90_codec;
	tlp.dcmpri = &dcmpri;
	tlp.dcmpro = &dcmpro;
	tlp.dres = &dres;
	de_dfilter_decompress_two_layer(c, &tlp);

	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	if(dres.bytes_consumed_valid) {
		de_dbg(c, "compressed data size: %"I64_FMT", ends at %"I64_FMT, dres.bytes_consumed,
			dcmpri.pos+dres.bytes_consumed);
		pos += dres.bytes_consumed;

		if(crunchctx->cksum_type==0) {
			crunchctx->checksum_calc &= 0xffff;
			crunchctx->checksum_reported = (UI)de_getu16le_p(&pos);
			de_dbg(c, "checksum (calculated): %u", crunchctx->checksum_calc);
			de_dbg(c, "checksum (reported): %u", crunchctx->checksum_reported);
			if(crunchctx->checksum_calc != crunchctx->checksum_reported) {
				de_err(c, "Checksum error. Decompression probably failed.");
				goto done;
			}
		}
	}

done:
	de_finfo_destroy(c, fi);
	dbuf_close(outf);
	de_dbg_indent(c, -1);
}

static void de_run_crunch(deark *c, de_module_params *mparams)
{
	struct crunch_ctx *crunchctx = NULL;
	i64 pos = 0;
	u8 b;
	u8 fmtver;
	const char *verstr;

	crunchctx = de_malloc(c, sizeof(struct crunch_ctx));

	pos += 2;
	if(!crcr_read_filename_etc(c, pos, &crunchctx->fnd)) goto done;
	pos += crunchctx->fnd.size;

	b = de_getbyte_p(&pos);
	de_dbg(c, "encoder version: 0x%02x", (UI)b);

	fmtver = de_getbyte_p(&pos);
	if(fmtver>=0x10 && fmtver<=0x1f) {
		verstr = "old";
	}
	else if(fmtver>=0x20 && fmtver<=0x2f) {
		verstr = "new";
	}
	else {
		verstr = "?";
	}
	de_dbg(c, "format version: 0x%02x (%s)", (UI)fmtver, verstr);

	crunchctx->cksum_type = de_getbyte_p(&pos);
	de_dbg(c, "checksum type: 0x%02x (%s)", (UI)crunchctx->cksum_type,
		(crunchctx->cksum_type==0?"standard":"?"));

	b = de_getbyte_p(&pos);
	de_dbg(c, "unused info byte: 0x%02x", (UI)b);

	de_dbg(c, "compressed data at %"I64_FMT, pos);
	if(fmtver>=0x20) {
		// v2 is by far the most common version, but it's not easy to support.
		// We support v1, only because it's easy.
		de_err(c, "This version of Crunch is not supported");
	}
	else {
		decompress_crunch_v1(c, crunchctx, pos);
	}

done:
	if(crunchctx) {
		crcr_filename_data_freecontents(c, &crunchctx->fnd);
		de_free(c, crunchctx);
	}
}

static int de_identify_crunch(deark *c)
{
	i64 id;

	id = de_getu16le(0);
	if(id==0xfe76) return 70;
	return 0;
}

void de_module_crunch(deark *c, struct deark_module_info *mi)
{
	mi->id = "crunch";
	mi->desc = "Crunch (CP/M)";
	mi->run_fn = de_run_crunch;
	mi->identify_fn = de_identify_crunch;
}

///////////////////////////////////////////////
// CRLZH - CP/M compressed file format

struct crlzh_ctx {
	struct crcr_filename_data fnd;
};

static void de_run_crlzh(deark *c, de_module_params *mparams)
{
	struct crlzh_ctx *crlzhctx = NULL;
	i64 pos = 0;
	u8 b;
	u8 fmtver;
	u8 cksum_type;
	const char *verstr;

	crlzhctx = de_malloc(c, sizeof(struct crlzh_ctx));

	pos += 2;
	if(!crcr_read_filename_etc(c, pos, &crlzhctx->fnd)) goto done;
	pos += crlzhctx->fnd.size;
	b = de_getbyte_p(&pos);
	de_dbg(c, "encoder version: 0x%02x", (UI)b);

	fmtver = de_getbyte_p(&pos);
	if(fmtver<=0x1f) {
		verstr = "old";
	}
	else if(fmtver>=0x20 && fmtver<=0x2f) {
		// Note: Alternatives are ==0x20 (CFX), and >=0x20 (lbrate).
		verstr = "new";
	}
	else {
		verstr = "?";
	}
	de_dbg(c, "format version: 0x%02x (%s)", (UI)fmtver, verstr);

	cksum_type = de_getbyte_p(&pos);
	de_dbg(c, "checksum type: 0x%02x (%s)", (UI)cksum_type,
		(cksum_type==0?"standard":"?"));

	b = de_getbyte_p(&pos);
	de_dbg(c, "unused info byte: 0x%02x", (UI)b);

	de_dbg(c, "compressed data at %"I64_FMT, pos);

done:
	if(crlzhctx) {
		crcr_filename_data_freecontents(c, &crlzhctx->fnd);
		de_free(c, crlzhctx);
	}
}

static int de_identify_crlzh(deark *c)
{
	i64 id;

	id = de_getu16le(0);
	if(id==0xfd76) return 70;
	return 0;
}

void de_module_crlzh(deark *c, struct deark_module_info *mi)
{
	mi->id = "crlzh";
	mi->desc = "CRLZH (CP/M)";
	mi->run_fn = de_run_crlzh;
	mi->identify_fn = de_identify_crlzh;
	mi->flags |= DE_MODFLAG_NONWORKING;
}

///////////////////////////////////////////////
// ZSQ (ZSQUSQ)
// LZW compression utility by W. Chin, A. Kumar.
// Format used by v1.0, 1985-10-26.

#define CODE_WACK 0x5741434bU

struct zsq_ctx {
	de_encoding input_encoding;
	de_ucstring *fn;
	UI checksum_reported;
	UI checksum_calc;
	struct de_timestamp timestamp;
};

static void zsq_writelistener_cb(dbuf *f, void *userdata, const u8 *buf, i64 buf_len)
{
	struct zsq_ctx *zsqctx = (struct zsq_ctx*)userdata;
	i64 i;

	for(i=0; i<buf_len; i++) {
		zsqctx->checksum_calc += buf[i];
	}
}

static void do_zsq_decompress(deark *c, struct zsq_ctx *zsqctx, i64 pos, dbuf *outf)
{
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	struct de_lzw_params delzwp;

	de_zeromem(&delzwp, sizeof(struct de_lzw_params));
	delzwp.fmt = DE_LZWFMT_ARC5;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = pos;
	dcmpri.len = c->infile->len - pos;
	dcmpro.f = outf;

	dbuf_set_writelistener(outf, zsq_writelistener_cb, (void*)zsqctx);

	fmtutil_decompress_lzw(c, &dcmpri, &dcmpro, &dres, &delzwp);

	zsqctx->checksum_calc &= 0xffff;
	de_dbg(c, "checksum (calculated): %u", (UI)zsqctx->checksum_calc);
	if(zsqctx->checksum_calc != zsqctx->checksum_reported) {
		de_err(c, "Checksum error. Decompression probably failed.");
	}
}

static void zsq_read_timestamp(deark *c, struct zsq_ctx *zsqctx, i64 pos)
{
	i64 dt_raw, tm_raw;
	char timestamp_buf[64];

	dt_raw = de_getu16le(pos);
	tm_raw = de_getu16le(pos+2);
	de_dos_datetime_to_timestamp(&zsqctx->timestamp, dt_raw, tm_raw);
	de_timestamp_to_string(&zsqctx->timestamp, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "timestamp: %s", timestamp_buf);
}

static void de_run_zsq(deark *c, de_module_params *mparams)
{
	struct zsq_ctx *zsqctx = NULL;
	i64 pos = 0;
	i64 hdr_len;
	i64 hdr_endpos;
	u32 id;
	dbuf *outf = NULL;
	de_finfo *fi = NULL;

	zsqctx = de_malloc(c, sizeof(struct zsq_ctx));
	zsqctx->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);

	id = (u32)de_getu32be_p(&pos);
	if(id != CODE_WACK) {
		de_err(c, "Not a ZSQ file");
		goto done;
	}

	fi = de_finfo_create(c);

	zsqctx->checksum_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "checksum (reported): %u", (UI)zsqctx->checksum_reported);

	hdr_len = de_getu16le_p(&pos);
	hdr_endpos = pos + hdr_len;
	if(hdr_endpos > c->infile->len) {
		de_err(c, "Bad header length");
		goto done;
	}

	zsq_read_timestamp(c, zsqctx, pos);
	pos += 4;

	zsqctx->fn = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, hdr_endpos-pos, 255, zsqctx->fn,
		DE_CONVFLAG_STOP_AT_NUL, zsqctx->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(zsqctx->fn));

	de_finfo_set_name_from_ucstring(c, fi, zsqctx->fn, 0);
	fi->original_filename_flag = 1;

	pos = hdr_endpos;
	de_dbg(c, "compressed data at %"I64_FMT, pos);

	outf = dbuf_create_output_file(c, NULL, fi, 0);

	do_zsq_decompress(c, zsqctx, pos, outf);

done:
	dbuf_close(outf);
	de_finfo_destroy(c, fi);
	if(zsqctx) {
		ucstring_destroy(zsqctx->fn);
		de_free(c, zsqctx);
	}
}

static int de_identify_zsq(deark *c)
{
	if(de_getu32be(0)==CODE_WACK) {
		return 90;
	}
	return 0;
}

void de_module_zsq(deark *c, struct deark_module_info *mi)
{
	mi->id = "zsq";
	mi->desc = "ZSQ (ZSQUSQ, LZW-compressed file)";
	mi->run_fn = de_run_zsq;
	mi->identify_fn = de_identify_zsq;
}

// **************************************************************************
// LZWCOM
// **************************************************************************

struct lzwcom_ctx {
	int ver; // 1, 2, or -1 if unknown
	struct de_crcobj *crco;
};

static void lzwcom_detect_version(deark *c, struct lzwcom_ctx *d)
{
	u32 crc_reported, crc_calc;

	if(c->infile->len < 1026) {
		d->ver = -1;
		return;
	}

	de_crcobj_reset(d->crco);
	de_crcobj_addslice(d->crco, c->infile, 0, 1024);
	crc_calc = de_crcobj_getval(d->crco); // Field only exists in v2 format
	crc_reported = (u32)de_getu16le(1024);
	if(crc_reported==crc_calc) {
		d->ver = 2;
	}
	else {
		d->ver = 1;
	}
}

static void de_run_lzwcom(deark *c, de_module_params *mparams)
{
	struct lzwcom_ctx *d = NULL;
	struct de_dfilter_ctx *dfctx = NULL;
	dbuf *outf = NULL;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	struct de_lzw_params delzwp;
	int errflag = 0;
	i64 pos = 0;
	const char *s;

	d = de_malloc(c, sizeof(struct lzwcom_ctx));
	d->ver = -1;
	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);

	s = de_get_ext_option(c, "lzwcom:version");
	if(s) {
		d->ver = de_atoi(s);
	}
	if(d->ver>=2) d->ver = 2;
	else if(d->ver!=1) d->ver = -1;

	if(d->ver == -1) {
		lzwcom_detect_version(c, d);
	}
	if(d->ver != -1) {
		de_declare_fmtf(c, "LZWCOM v%d", d->ver);
	}
	else {
		de_declare_fmt(c, "LZWCOM (unknown version)");
	}

	outf = dbuf_create_output_file(c, "unc", NULL, 0);
	de_dfilter_init_objects(c, NULL, &dcmpro, &dres);
	dcmpro.f = outf;

	de_zeromem(&delzwp, sizeof(struct de_lzw_params));
	delzwp.fmt = DE_LZWFMT_ARC5;
	delzwp.flags |= DE_LZWFLAG_TOLERATETRAILINGJUNK;
	dfctx = de_dfilter_create(c, dfilter_lzw_codec, (void*)&delzwp, &dcmpro, &dres);

	while(1) {
		i64 block_dlen;
		i64 block_pos = pos;

		if(dres.errcode) break;
		if(dfctx->finished_flag) break;
		if(pos >= c->infile->len) break;
		block_dlen = de_min_int(1024, c->infile->len - pos);

		if(d->ver==2) {
			de_dbg(c, "block at %"I64_FMT", dlen=%"I64_FMT, block_pos, block_dlen);
		}

		de_dfilter_addslice(dfctx, c->infile, pos, block_dlen);

		// Oddly, this format includes CRCs of the *compressed* bytes, instead of
		// of the decompressed bytes. So it doesn't detect incorrect decompression.
		if(d->ver==2) {
			de_crcobj_reset(d->crco);
			de_crcobj_addslice(d->crco, c->infile, pos, block_dlen);
		}

		pos += block_dlen;

		if(d->ver==2) {
			u32 crc_reported, crc_calc;

			if(c->infile->len - pos < 2) break;
			crc_calc = de_crcobj_getval(d->crco);
			crc_reported = (u32)de_getu16le_p(&pos);
			de_dbg_indent(c, 1);
			de_dbg(c, "crc (calculated): 0x%04x", (UI)crc_calc);
			de_dbg(c, "crc (reported): 0x%04x", (UI)crc_reported);
			de_dbg_indent(c,- 1);
			if(!errflag && crc_calc!=crc_reported) {
				de_warn(c, "CRC check failed at %"I64_FMT". This might not be an LZWCOM v2 file.", pos-2);
				errflag = 1;
			}
		}
	}

	de_dfilter_finish(dfctx);
	if(dres.errcode) {
		de_err(c, "Decompression failed: %s", de_dfilter_get_errmsg(c, &dres));
	}

	de_dfilter_destroy(dfctx);
	dbuf_close(outf);
	if(d) {
		de_crcobj_destroy(d->crco);
		de_free(c, d);
	}
}

static void de_help_lzwcom(deark *c)
{
	de_msg(c, "-opt lzwcom:version=<1|2> : The format version");
}

void de_module_lzwcom(deark *c, struct deark_module_info *mi)
{
	mi->id = "lzwcom";
	mi->desc = "LZWCOM compressed file";
	mi->run_fn = de_run_lzwcom;
	mi->identify_fn = NULL;
	mi->help_fn = de_help_lzwcom;
}
