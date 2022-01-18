// This file is part of Deark.
// Copyright (C) 2017 Jason Summers
// See the file COPYING for terms of use.

// ZOO compressed archive format

// The ZOO parser in this file was originally derived from unzoo.c v4.4
// by Martin Schoenert.
// The original file had this notice:

/*
*A  unzoo.c                     Tools                        Martin Schoenert
**
*H  @(#)$Id: unzoo.c,v 4.4 2000/05/29 08:56:57 sal Exp $
**
*Y  This file is in the Public Domain.
*/

// To be clear, the code in this file (Deark's zoo.c file) is covered by
// Deark's standard terms of use.

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>

DE_DECLARE_MODULE(de_module_zoo);
DE_DECLARE_MODULE(de_module_zoo_filter);
DE_DECLARE_MODULE(de_module_zoo_z);

#define ZOO_SIGNATURE  0xfdc4a7dcU

#define ZOOCMPR_STORED  0
#define ZOOCMPR_LZD     1
#define ZOOCMPR_LZH     2

struct localctx_struct;
typedef struct localctx_struct lctx;
struct member_data;

// Data associated with one Zoo member file
struct member_data {
	de_finfo *fi;
	de_ucstring *fullname;
	u8             type;           /* type of current member (1)      */
	u8             method;         /* packing method of member (0..2) */
	u8 has_ext_header;
	i64 next_member_hdr_pos;
	i64 cmpr_pos;
	i64 cmpr_len;
	i64 uncmpr_len;
	i64 comment_pos;
	i64 comment_len; // 0 if no comment
	unsigned int datdos;         /* date (in DOS format)            */
	unsigned int timdos;         /* time (in DOS format)            */
	u32 crc_reported;
	u32 crc_calculated;
	u32 crc_hdr_reported;
	u32 crc_hdr_calculated;
	u8             majver;         /* major version needed to extract */
	u8             minver;         /* minor version needed to extract */
	u8 is_deleted;        /* 1 if member is deleted, 0 else  */
	u8             timzon;         /* time zone                       */
	unsigned int system;         /* system identifier               */
	u32 attribs;         /* file permissions                */
	u8 vflag;         /* gens. on, last gen., gen. limit */
	unsigned int ver;            /* version number of member        */
};

struct localctx_struct {
	int input_encoding;
	int extract_comments_to_files;
	int undelete;
	struct de_inthashtable *offsets_seen;

	i64 first_member_hdr_pos;
	u8 majver;
	u8 minver;
	u8 type;  // archive header version
	i64 archive_comment_pos;
	i64 archive_comment_len; // 0 if no comment
	u8 vdata;         /* gens. on, gen. limit            */

	int num_deleted_files_found;
	i64 min_offset_found;

	// Shared by all member files, so we don't have to recalculate the CRC table
	// for each member file.
	struct de_crcobj *crco;
};

// An offset is considered meaningful if len!=0.
static void on_offset_found(deark *c, lctx *d, i64 pos, i64 len)
{
	if(len==0 || pos<0) return;
	if(pos<d->min_offset_found) {
		d->min_offset_found = pos;
	}
}

static const char *get_member_name_for_msg(deark *c, lctx *d, struct member_data *md)
{
	if(md && ucstring_isnonempty(md->fullname)) {
		return ucstring_getpsz_d(md->fullname);
	}
	return "(?)";
}

static void do_extract_comment(deark *c, lctx *d, i64 pos, i64 len, int is_main)
{
	dbuf *outf = NULL;

	outf = dbuf_create_output_file(c, "comment.txt", NULL, DE_CREATEFLAG_IS_AUX);
	dbuf_copy_slice_convert_to_utf8(c->infile, pos, len,
		DE_EXTENC_MAKE(d->input_encoding, DE_ENCSUBTYPE_HYBRID),
		outf, 0x2|0x4);
	dbuf_close(outf);
}

static void do_dbg_comment(deark *c, lctx *d, i64 pos, i64 len, const char *name,
	int is_main)
{
	de_ucstring *s = NULL;

	if(c->debug_level<1) return;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, len, DE_DBG_MAX_STRLEN, s,
		0, DE_EXTENC_MAKE(d->input_encoding, DE_ENCSUBTYPE_HYBRID));
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static void do_comment(deark *c, lctx *d, i64 pos, i64 len, const char *name,
	int is_main, int extract_to_file)
{
	on_offset_found(c, d, pos, len);
	if(len<1) return;
	if(pos<0 || pos+len>c->infile->len) return;
	if(extract_to_file) {
		do_extract_comment(c, d, pos, len, is_main);
	}
	else {
		do_dbg_comment(c, d, pos, len, name, is_main);
	}
}

// Read the main file header
static int do_global_header(deark *c, lctx *d, i64 pos1)
{
	i64 pos = pos1;
	int retval = 0;
	unsigned int sig;
	u32 zoo_minus, zoo_minus_expected;
	i64 i;
	de_ucstring *txt = NULL;

	de_dbg(c, "archive header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	// Intro text, e.g. "ZOO 2.10 Archive."
	// Zoo source code (zoo.h) says "The contents of the text message are [...]
	// not used by Zoo and they may be anything.".
	txt = ucstring_create(c);
	for(i=0; i<20; i++) {
		u8 ch;

		ch = de_getbyte(pos+i);
		if(ch==26 || ch==0) break;
		if(ch<32 || ch>126) ch = '_';
		ucstring_append_char(txt, (de_rune)ch);
	}
	de_dbg(c, "header text: \"%s\"", ucstring_getpsz_d(txt));
	pos += 20;

	sig = (unsigned int)de_getu32le_p(&pos);
	if (sig != ZOO_SIGNATURE) goto done;

	d->first_member_hdr_pos = de_getu32le_p(&pos);
	de_dbg(c, "first entry pos: %"I64_FMT, d->first_member_hdr_pos);

	zoo_minus = (u32)de_getu32le_p(&pos);
	de_dbg(c, "consistency check: 0x%08x", (UI)zoo_minus);
	zoo_minus_expected = (u32)((~(u32)d->first_member_hdr_pos)+(u32)1);
	if(zoo_minus!=zoo_minus_expected) {
		de_warn(c, "Archive header failed consistency check (is 0x%08x, expected 0x%08x)",
			(UI)zoo_minus, (UI)zoo_minus_expected);
	}

	// Note: The version number fields are sometimes erroneously documented as
	// "version made by" and "version needed to extract [all files]".
	d->majver = de_getbyte_p(&pos);
	d->minver = de_getbyte_p(&pos);
	de_dbg(c, "version needed to manipulate archive: %d.%d", (int)d->majver, (int)d->minver);

	// Fields that aren't present in old versions.
	if(d->first_member_hdr_pos > 34) {
		d->type = de_getbyte_p(&pos);
		de_dbg(c, "archive header format version (\"type\"): %u", (unsigned int)d->type);
		// 1 is the only value here with a known meaning, but we'll accept some slightly
		// higher values, and assume they are backward-compatible.
		if(d->type<1 || d->type>5) {
			d->type = 0;
			goto after_ext_hdr;
		}

		d->archive_comment_pos = de_getu32le_p(&pos);
		d->archive_comment_len = de_getu16le_p(&pos);
		de_dbg(c, "archive comment pos: %"I64_FMT", len=%d", d->archive_comment_pos,
			(int)d->archive_comment_len);
		do_comment(c, d, d->archive_comment_pos, d->archive_comment_len, "archive comment",
			1, d->extract_comments_to_files);

		d->vdata = de_getbyte_p(&pos);
		de_dbg(c, "archive-level versioning settings (\"vdata\"): 0x%02x", (UI)d->vdata);
	}
after_ext_hdr:

	retval = 1;

done:
	ucstring_destroy(txt);
	de_dbg_indent(c, -1);
	return retval;
}

static const char *get_cmpr_meth_name(u8 t)
{
	const char *name = NULL;
	switch(t) {
	case 0: name="stored"; break;
	case 1: name="lzd"; break;
	case 2: name="lzh"; break;
	}
	return name?name:"?";
}

// To be called after all mod_time-related fields have been read.
// Finish reporting the mod_time, and set md->fi->mod_time.
static void finish_modtime_decoding(deark *c, lctx *d, struct member_data *md)
{
	i64 timestamp_offset;
	char timestamp_buf[64];

	timestamp_offset = 0;
	if      ( md->timzon < 127 )  timestamp_offset = 15*60*((i64)md->timzon      );
	else if ( 127 < md->timzon )  timestamp_offset = 15*60*((i64)md->timzon - 256);

	de_dos_datetime_to_timestamp(&md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY], (i64)md->datdos, (i64)md->timdos);
	de_timestamp_to_string(&md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY], timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "mod time: %s", timestamp_buf);
	if(md->timzon == 127) {
		md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY].tzcode = DE_TZCODE_LOCAL;
	}
	else {
		de_timestamp_cvt_to_utc(&md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY], timestamp_offset);
		de_timestamp_to_string(&md->fi->timestamp[DE_TIMESTAMPIDX_MODIFY], timestamp_buf, sizeof(timestamp_buf), 0);
		de_dbg(c, "mod time (UTC): %s", timestamp_buf);
	}
}

static void calc_hdr_crc(deark *c, lctx *d, struct member_data *md, i64 pos1, i64 lvar)
{
	de_crcobj_reset(d->crco);
	de_crcobj_addslice(d->crco, c->infile, pos1, 54);
	de_crcobj_addzeroes(d->crco, 2);
	de_crcobj_addslice(d->crco, c->infile, pos1+56, lvar);
	md->crc_hdr_calculated = de_crcobj_getval(d->crco);
}

// Decode the trailer member. Only a few fields are potentially interesting; the
// rest are usually zeroed out.
// This code is duplicated in do_member_header(), but it's too much trouble to
// share it.
static void do_member_eof(deark *c, lctx *d, struct member_data *md, i64 pos1)
{
	i64 lvar;

	if(!md->has_ext_header) goto done;
	lvar = de_getu16le(pos1+51);
	de_dbg(c, "length of variable part: %d", (int)lvar);

	md->crc_hdr_reported = (u32)de_getu16le(pos1+54);
	de_dbg(c, "entry crc (reported): 0x%04x", (unsigned int)md->crc_hdr_reported);
	calc_hdr_crc(c, d, md, pos1, lvar);
	de_dbg(c, "entry crc (calculated): 0x%04x", (UI)md->crc_hdr_calculated);
	if(md->crc_hdr_calculated != md->crc_hdr_reported) {
		de_warn(c, "Header CRC check failed");
	}

done:
	;
}

static int do_member_header(deark *c, lctx *d, struct member_data *md, i64 pos1)
{
	de_ucstring *shortname = NULL;
	de_ucstring *longname = NULL;
	de_ucstring *dirname = NULL;
	int retval = 0;
	i64 pos = pos1;
	i64 hdr_endpos;
	i64 lvar;           /* length of variable part         */
	i64 lnamu;          /* length of long name             */
	i64 ldiru;          /* length of directory             */
	unsigned int sig;
	UI attribs_type;
	char descrbuf[80];

	sig = (unsigned int)de_getu32le_p(&pos);
	if(sig != ZOO_SIGNATURE) {
		de_err(c, "Malformed Zoo file, bad magic number at %"I64_FMT, pos1);
		goto done;
	}

	/* read the fixed part of the directory entry                          */
	md->type   = de_getbyte_p(&pos);
	md->has_ext_header = (u8)(md->type == 2);
	md->method = de_getbyte_p(&pos);
	md->next_member_hdr_pos = de_getu32le_p(&pos);

	de_dbg(c, "member header format version (\"type\"): %d", (int)md->type);
	if(md->next_member_hdr_pos) {
		de_dbg(c, "compression method: %d (%s)", (int)md->method, get_cmpr_meth_name(md->method));
	}

	de_snprintf(descrbuf, sizeof(descrbuf), (md->next_member_hdr_pos?"":
		" (none - This is the trailer record)"));
	de_dbg(c, "next entry pos: %"I64_FMT"%s", md->next_member_hdr_pos, descrbuf);

	if(md->next_member_hdr_pos==0) {
		do_member_eof(c, d, md, pos1);
		retval = 1;
		goto done;
	}

	md->cmpr_pos = de_getu32le_p(&pos);
	de_dbg(c, "pos of file data: %"I64_FMT, md->cmpr_pos);

	md->datdos = (unsigned int)de_getu16le_p(&pos);
	md->timdos = (unsigned int)de_getu16le_p(&pos);
	de_dbg2(c, "dos date,time: %u,%u", md->datdos, md->timdos);
	if(!md->has_ext_header) {
		md->timzon = 127;
		finish_modtime_decoding(c, d, md);
	}

	md->crc_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "file data crc (reported): 0x%04x", (unsigned int)md->crc_reported);
	md->uncmpr_len = de_getu32le_p(&pos);
	de_dbg(c, "original size: %"I64_FMT, md->uncmpr_len);
	md->cmpr_len = de_getu32le_p(&pos);
	de_dbg(c, "compressed size: %"I64_FMT, md->cmpr_len);

	// Note: The version number fields are sometimes erroneously documented as
	// "version made by" and "version needed". But (according to Zoo 2.10),
	// there is no "version made by" field.
	md->majver = de_getbyte_p(&pos);
	md->minver = de_getbyte_p(&pos);
	de_dbg(c, "version needed to extract: %d.%d", (int)md->majver, (int)md->minver);

	md->is_deleted = de_getbyte_p(&pos);
	de_dbg(c, "is deleted: %d", (int)md->is_deleted);
	pos++; // "file structure" (?)
	md->comment_pos = de_getu32le_p(&pos);
	md->comment_len = de_getu16le_p(&pos);
	de_dbg(c, "comment pos: %"I64_FMT", len=%d", md->comment_pos, (int)md->comment_len);
	do_comment(c, d, md->comment_pos, md->comment_len, "comment", 0,
		(d->extract_comments_to_files) && (!md->is_deleted || d->undelete));

	// In "type 2" header format, the shortname field is a fixed 13 bytes, and is
	// followed by other fields.
	// In "type 1" header format, the shortname field is (allegedly) the last field
	// in the header, and it's supposed to be NUL-terminated, so it's hard to be
	// *sure* what size it is.
	// Zoo 1.21 seems to leave room for 14 bytes, instead of the 13 that would be
	// expected. And it seemingly allows up to 14-byte filenames with no NUL -- but
	// this could well be a bug. Or perhaps the 13-byte filename field is followed
	// by a 1-byte field of unknown purpose.
	shortname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 13, shortname, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "short name: \"%s\"", ucstring_getpsz(shortname));
	pos += 13;

	if(!md->has_ext_header) {
		goto done_with_header;
	}

	// If has_ext_header, there are at least 3 more header fields:
	//  2-byte length-of-variable-part
	//  1-byte timezone
	//  2-byte CRC of dir entry

	lvar   = de_getu16le_p(&pos);
	de_dbg(c, "length of variable part: %d", (int)lvar);

	md->timzon = de_getbyte_p(&pos);

	// Note: The timezone field is definitely a signed byte that is the
	// number of 15-minute units from UTC, but it is unknown to me whether
	// a positive number means west, or east. Under either interpretation,
	// I have multiple sample files with highly implausible timezones. The
	// interpretation used here is based on the preponderance of evidence.
	if(md->timzon==127) {
		de_strlcpy(descrbuf, "unknown", sizeof(descrbuf));
	}
	else if(md->timzon>127) {
		de_snprintf(descrbuf, sizeof(descrbuf), "%.2f hours east of UTC",
			((double)md->timzon - 256.0)/-4.0);
	}
	else {
		de_snprintf(descrbuf, sizeof(descrbuf), "%.2f hours west of UTC",
			((double)md->timzon)/4.0);
	}
	de_dbg(c, "time zone: %d (%s)", (int)md->timzon, descrbuf);
	finish_modtime_decoding(c, d, md);

	md->crc_hdr_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "entry crc (reported): 0x%04x", (unsigned int)md->crc_hdr_reported);
	calc_hdr_crc(c, d, md, pos1, lvar);
	de_dbg(c, "entry crc (calculated): 0x%04x", (UI)md->crc_hdr_calculated);
	if(md->crc_hdr_calculated != md->crc_hdr_reported) {
		de_warn(c, "Header CRC check failed");
	}

	// The "variable part" of the extended header begins here.
	hdr_endpos = pos + lvar;

	if(hdr_endpos-pos < 1) goto done_with_header;
	lnamu = (i64)de_getbyte_p(&pos);
	de_dbg2(c, "long name len: %d", (int)lnamu);

	if(hdr_endpos-pos < 1) goto done_with_header;
	ldiru = (i64)de_getbyte_p(&pos);
	de_dbg2(c, "dir name len: %d", (int)ldiru);

	if(hdr_endpos-pos < lnamu) goto done_with_header;
	if(lnamu>0) {
		longname = ucstring_create(c);
		dbuf_read_to_ucstring(c->infile, pos, lnamu, longname,
			DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
		de_dbg(c, "long name: \"%s\"", ucstring_getpsz(longname));
	}
	pos += lnamu;

	if(hdr_endpos-pos < ldiru) goto done_with_header;
	if(ldiru>0) {
		dirname = ucstring_create(c);
		dbuf_read_to_ucstring(c->infile, pos, ldiru, dirname,
			DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
		de_dbg(c, "dir name: \"%s\"", ucstring_getpsz(dirname));
	}
	pos += ldiru;

	if(hdr_endpos-pos < 2) goto done_with_header;
	md->system = (unsigned int)de_getu16le_p(&pos);
	de_dbg(c, "system id: %u", md->system);

	if(hdr_endpos-pos < 3) goto done_with_header;
	md->attribs = (u32)dbuf_getint_ext(c->infile, pos, 3, 1, 0);
	pos += 3;
	de_dbg(c, "attribs: 0x%06x", (UI)md->attribs);
	de_dbg_indent(c, 1);
	attribs_type = (md->attribs >> 22);
	de_dbg(c, "attribs type: %u", attribs_type);
	if(attribs_type == 1) {
		de_dbg(c, "perms: octal(%o)", (UI)(md->attribs & 0x1ff));
		if((md->attribs & 0111) != 0) {
			md->fi->mode_flags |= DE_MODEFLAG_EXE;
		}
		else {
			md->fi->mode_flags |= DE_MODEFLAG_NONEXE;
		}
	}
	de_dbg_indent(c, -1);

	if(hdr_endpos-pos < 1) goto done_with_header;
	md->vflag = de_getbyte_p(&pos);
	de_dbg(c, "versioning settings (\"vflag\"): 0x%02x", (UI)md->vflag);

	if(hdr_endpos-pos < 2) goto done_with_header;
	md->ver = (unsigned int)de_getu16le_p(&pos);
	de_dbg(c, "file version number: %u", md->ver);

done_with_header:
	// Note: Typically, there is a 5-byte "file leader" ("@)#(\0") here, between
	// the member header and the member data, so pos is not
	// expected to equal md->posdat.

	// Figure out the best filename to use
	if(ucstring_isnonempty(longname) || ucstring_isnonempty(shortname)) {
		if(ucstring_isnonempty(dirname)) {
			ucstring_append_ucstring(md->fullname, dirname);
			ucstring_append_sz(md->fullname, "/", DE_ENCODING_LATIN1);
		}
		if(ucstring_isnonempty(longname)) {
			ucstring_append_ucstring(md->fullname, longname);
		}
		else if(ucstring_isnonempty(shortname)) {
			ucstring_append_ucstring(md->fullname, shortname);
		}

		if(ucstring_isempty(md->fullname)) {
			ucstring_append_sz(md->fullname, "_", DE_ENCODING_LATIN1);
		}
		if(md->is_deleted) {
			ucstring_printf(md->fullname, DE_ENCODING_LATIN1, ".deleted%02d",
				d->num_deleted_files_found);
		}

		de_finfo_set_name_from_ucstring(c, md->fi, md->fullname, DE_SNFLAG_FULLPATH);
		md->fi->original_filename_flag = 1;
	}

	retval = 1;

done:
	ucstring_destroy(shortname);
	ucstring_destroy(longname);
	ucstring_destroy(dirname);
	return retval;
}

static void decompress_lzd(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	struct de_lzw_params delzwp;

	de_zeromem(&delzwp, sizeof(struct de_lzw_params));
	delzwp.fmt = DE_LZWFMT_ZOOLZD;
	delzwp.max_code_size = 13;
	fmtutil_decompress_lzw(c, dcmpri, dcmpro, dres, &delzwp);
}

static void decompress_lzh(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	struct de_lh5x_params lzhparams;

	de_zeromem(&lzhparams, sizeof(struct de_lh5x_params));
	lzhparams.fmt = DE_LH5X_FMT_LH5;
	lzhparams.zero_codes_block_behavior = DE_LH5X_ZCB_STOP;
	lzhparams.warn_about_zero_codes_block = 0;

	// Zoo does not appear to allow LZ77 offsets that point to data before
	// the beginning of the file, so it doesn't matter what we initialize the
	// history buffer to.
	lzhparams.history_fill_val = 0x00;

	fmtutil_decompress_lh5x(c, dcmpri, dcmpro, dres, &lzhparams);
}

// Process a single member file (or "trailer" record).
// If there are more members after this, sets *next_member_hdr_pos to nonzero.
static void do_member(deark *c, lctx *d, i64 pos1, i64 *next_member_hdr_pos)
{
	struct member_data *md = NULL;
	dbuf *outf = NULL;
	const char *ext;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	on_offset_found(c, d, pos1, 1);

	md = de_malloc(c, sizeof(struct member_data));
	md->fi = de_finfo_create(c);
	md->fullname = ucstring_create(c);

	if (!do_member_header(c, d, md, pos1)) {
		goto done;
	}
	on_offset_found(c, d, md->cmpr_pos, md->cmpr_len);

	*next_member_hdr_pos = md->next_member_hdr_pos;

	if ( ! md->next_member_hdr_pos ) {
		goto done;
	}

	if(md->is_deleted && !d->undelete) {
		de_dbg(c, "ignoring deleted entry");
		goto done;
	}

	if ( (md->majver>2) || (md->majver==2 && md->minver>1) ) {
		de_err(c, "%s: Unsupported format version: %d.%d",
			get_member_name_for_msg(c, d, md),
			(int)md->majver, (int)md->minver);
		goto done;
	}

	if(md->method!=ZOOCMPR_STORED && md->method!=ZOOCMPR_LZD && md->method!=ZOOCMPR_LZH) {
		de_err(c, "%s: Unsupported compression method: %d",
			get_member_name_for_msg(c, d, md), (int)md->method);
		goto done;
	}

	de_dbg(c, "compressed data at %"I64_FMT", len=%"I64_FMT, md->cmpr_pos,
		md->cmpr_len);

	if(md->cmpr_pos + md->cmpr_len > c->infile->len) {
		de_err(c, "%s: Data goes beyond end of file", get_member_name_for_msg(c, d, md));
		goto done;
	}

	// Ready to decompress. Set up the output file.
	if(md->fi && md->fi->original_filename_flag) {
		ext = NULL;
	}
	else {
		ext = "bin";
	}
	outf = dbuf_create_output_file(c, ext, md->fi, 0);
	dbuf_enable_wbuffer(outf);
	dbuf_set_writelistener(outf, de_writelistener_for_crc, (void*)d->crco);
	de_crcobj_reset(d->crco);

	dcmpri.f = c->infile;
	dcmpri.pos = md->cmpr_pos;
	dcmpri.len = md->cmpr_len;

	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = md->uncmpr_len;

	de_dbg_indent(c, 1);
	switch(md->method) {
	case ZOOCMPR_STORED:
		fmtutil_decompress_uncompressed(c, &dcmpri, &dcmpro, &dres, 0);
		break;
	case ZOOCMPR_LZD:
		decompress_lzd(c, &dcmpri, &dcmpro, &dres);
		break;
	case ZOOCMPR_LZH:
		decompress_lzh(c, &dcmpri, &dcmpro, &dres);
		break;
	default:
		goto done; // Should be impossible
	}
	dbuf_flush(dcmpro.f);
	de_dbg_indent(c, -1);

	md->crc_calculated = de_crcobj_getval(d->crco);
	if(!dres.errcode) {
		de_dbg(c, "file data crc (calculated): 0x%04x", (unsigned int)md->crc_calculated);
	}

	if(dres.errcode) {
		de_err(c, "%s: %s", get_member_name_for_msg(c, d, md),
			de_dfilter_get_errmsg(c, &dres));
	}
	else if(outf->len != md->uncmpr_len) {
		de_err(c, "%s: Expected %"I64_FMT" uncompressed bytes, got %"I64_FMT,
			get_member_name_for_msg(c, d, md), md->uncmpr_len, outf->len);
	}
	else if (md->crc_calculated != md->crc_reported) {
		de_err(c, "%s: CRC check failed", get_member_name_for_msg(c, d, md));
	}

done:
	dbuf_close(outf);
	if(md) {
		if(md->is_deleted) d->num_deleted_files_found++;
		ucstring_destroy(md->fullname);
		de_finfo_destroy(c, md->fi);
		de_free(c, md);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

// The archive comment can be anywhere in the file, but Zoo normally
// puts it right after the archive header, at offset 42.
// I have a number of Zoo files in which a distributor has added their
// own comment at the end of the file, leaving the original comment
// intact but invisible.
static void check_for_orphaned_comment(deark *c, lctx *d)
{
	i64 ocpos, oclen;
	i64 foundpos = 0;

	if(d->type != 1) return;
	if(d->archive_comment_pos==0 || d->archive_comment_len==0) return;
	ocpos = 42;
	if(d->min_offset_found <= ocpos) return;
	oclen = d->min_offset_found - ocpos;
	if(oclen<5 || oclen>1000) return;
	if(de_getbyte(ocpos+oclen-1) != 0x0a) return;
	if(dbuf_search_byte(c->infile, 0x00, ocpos, oclen, &foundpos)) return;
	de_dbg(c, "possible orphaned archive comment found at %"I64_FMT", len=%"I64_FMT,
		ocpos, oclen);
	do_comment(c, d, ocpos, oclen, "orphaned archive comment", 1, 0);
}

// The main function: process a Zoo file
static void de_run_zoo(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(lctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_ASCII);
	d->undelete = de_get_ext_option_bool(c, "zoo:undelete", 0);
	d->extract_comments_to_files = (c->extract_level>=2);

	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);
	d->min_offset_found = c->infile->len;

	if(!do_global_header(c, d, pos)) {
		de_err(c, "Bad global header");
		goto done;
	}

	/* loop over the members of the archive                                */
	d->offsets_seen = de_inthashtable_create(c); // For protection against infinite loops
	pos = d->first_member_hdr_pos;
	while ( 1 ) {
		i64 next_member_hdr_pos;

		de_dbg_indent_restore(c, saved_indent_level);

		if(pos==0) break;

		if(pos >= c->infile->len) {
			de_err(c, "Unexpected EOF, expected member header at %"I64_FMT, pos);
			goto after_members;
		}

		if(!de_inthashtable_add_item(c, d->offsets_seen, pos, NULL)) {
			de_err(c, "Loop detected");
			goto after_members;
		}

		de_dbg(c, "entry at %"I64_FMT, pos);
		de_dbg_indent(c, 1);

		next_member_hdr_pos = 0;
		do_member(c, d, pos, &next_member_hdr_pos);
		pos = next_member_hdr_pos;
	}

after_members:
	check_for_orphaned_comment(c, d);

	if(d->num_deleted_files_found>0 && !d->undelete) {
		de_info(c, "Note: %d deleted file(s) found. Use \"-opt zoo:undelete\" "
			"to extract them.", d->num_deleted_files_found);
	}

done:
	if(d) {
		de_inthashtable_destroy(c, d->offsets_seen);
		de_crcobj_destroy(d->crco);
		de_free(c, d);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static int de_identify_zoo(deark *c)
{
	if(!dbuf_memcmp(c->infile, 20, "\xdc\xa7\xc4\xfd", 4))
		return 100;
	return 0;
}

static void de_help_zoo(deark *c)
{
	de_msg(c, "-opt zoo:undelete : Also extract deleted files");
}

void de_module_zoo(deark *c, struct deark_module_info *mi)
{
	mi->id = "zoo";
	mi->desc = "Zoo compressed archive format";
	mi->run_fn = de_run_zoo;
	mi->identify_fn = de_identify_zoo;
	mi->help_fn = de_help_zoo;
}

/////////////////////

static void de_run_zoo_filter(deark *c, de_module_params *mparams)
{
	dbuf *outf = NULL;
	struct de_crcobj *crco = NULL;
	int use_lzh = 0;
	u32 crc_reported;
	u32 crc_calculated;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	if(c->infile->len<6) goto done;

	use_lzh = de_get_ext_option_bool(c, "zoo_filter:lzh", -1);
	if(use_lzh<0) {
		if(dbuf_is_all_zeroes(c->infile, c->infile->len-4, 2)) {
			use_lzh = 1;
		}
		else {
			use_lzh = 0;
		}
	}

	de_declare_fmtf(c, "Zoo filter, LZ%s", (use_lzh?"H":"D"));

	crc_reported = (u32)de_getu32le(c->infile->len-2);
	de_dbg(c, "crc (reported): 0x%04x", (UI)crc_reported);

	outf = dbuf_create_output_file(c, "bin", NULL, 0);
	dbuf_enable_wbuffer(outf);
	crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);
	dbuf_set_writelistener(outf, de_writelistener_for_crc, (void*)crco);

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);
	dcmpri.f = c->infile;
	dcmpri.pos = 2;
	dcmpri.len = c->infile->len - 4;

	dcmpro.f = outf;
	dcmpro.len_known = 0;

	if(use_lzh) {
		decompress_lzh(c, &dcmpri, &dcmpro, &dres);
	}
	else {
		decompress_lzd(c, &dcmpri, &dcmpro, &dres);
	}
	dbuf_flush(dcmpro.f);

	if(dres.errcode) {
		de_err(c, "%s", de_dfilter_get_errmsg(c, &dres));
		goto done;
	}

	crc_calculated = de_crcobj_getval(crco);
	de_dbg(c, "crc (calculated): 0x%04x", (UI)crc_calculated);
	if(crc_calculated != crc_reported) {
		de_err(c, "CRC check failed");
		goto done;
	}

done:
	dbuf_close(outf);
	de_crcobj_destroy(crco);
}

static int de_identify_zoo_filter(deark *c)
{
	u8 b[2];

	if(c->infile->len<6) return 0;
	if(de_getu16le(0) != 0x5a32) return 0;

	// LZH ends with 16 0 bits, followed by 0 to 7 bits of padding that we
	// will hope are 0. So it must end with two 0x00 bytes.
	// LZD ends with the EOF code: 257. By my calculation, one of the 1 bits
	// from that code must occur in the second-to-last byte. And the last byte
	// can have at most one '1' bit.
	de_read(b, c->infile->len-4, 2);
	if(b[0]==0) {
		if(b[1]==0) return 45; // Possible LZH
	}
	else {
		if(b[1]<=0x02 || b[1]==0x04 || b[1]==0x08 || b[1]==0x10 ||
			b[1]==0x20 || b[1]==0x40 || b[1]==0x80)
		{
			return 45; // Possible LZD
		}
	}
	return 0;
}

void de_module_zoo_filter(deark *c, struct deark_module_info *mi)
{
	mi->id = "zoo_filter";
	mi->desc = "Zoo filter format";
	mi->run_fn = de_run_zoo_filter;
	mi->identify_fn = de_identify_zoo_filter;
}

/////////////////////

struct zoo_z_ctx {
	i64 outf_member_pos;
	i64 outf_comment_pos;
	i64 comment_len;
	i64 outf_leader_pos;
	i64 outf_cmpr_pos;
	i64 cmpr_len;
	i64 outf_trailer_pos;
	i64 inf_comment_pos;
	i64 inf_cmpr_pos;
};

// Convert Zoo Z format to Zoo format
// TODO?: Write to Zoo 2.x format instead of 1.20 format. But it's more trouble.
static void de_run_zoo_z(deark *c, de_module_params *mparams)
{
	dbuf *outf = NULL;
	static const u8 archivehdr[34] = {0x5a,0x4f,0x4f,0x20,0x31,0x2e,0x32,0x30,0x20,0x41,
		0x72,0x63,0x68,0x69,0x76,0x65,0x2e,0x1a,0x00,0x00,0xdc,0xa7,0xc4,0xfd,0x22,0x00,
		0x00,0x00,0xde,0xff,0xff,0xff,0x01,0x01};
	struct zoo_z_ctx *zctx = NULL;
	int need_errmsg = 0;

	de_declare_fmtf(c, "Zoo Z, DOS-compatible");

	zctx = de_malloc(c, sizeof(struct zoo_z_ctx));
	if(dbuf_memcmp(c->infile, 0, "\xfe\x07\x01", 3)) {
		de_err(c, "File not in Zoo Z format, or not a supported version");
		goto done;
	}

	need_errmsg = 1;
	zctx->cmpr_len = de_getu32le(14);
	de_dbg(c, "compressed size: %"I64_FMT, zctx->cmpr_len);
	zctx->comment_len = de_getu16le(20);
	de_dbg(c, "comment: size=%d", (int)zctx->comment_len);

	// Figure out where everything will go.
	zctx->outf_member_pos = 34;
	zctx->outf_leader_pos = zctx->outf_member_pos + 52;
	zctx->outf_cmpr_pos = zctx->outf_leader_pos + 5;
	zctx->outf_comment_pos = zctx->outf_cmpr_pos + zctx->cmpr_len;
	zctx->outf_trailer_pos = zctx->outf_comment_pos + zctx->comment_len;
	zctx->inf_comment_pos = 36;
	zctx->inf_cmpr_pos = zctx->inf_comment_pos + zctx->comment_len;

	if(zctx->inf_comment_pos+zctx->comment_len > c->infile->len) goto done;
	if(zctx->inf_cmpr_pos+zctx->cmpr_len > c->infile->len) goto done;

	outf = dbuf_create_output_file(c, "zoo", NULL, 0);

	// Archive header
	dbuf_write(outf, archivehdr, 34);

	// Main member header
	dbuf_writeu32le(outf, ZOO_SIGNATURE);
	dbuf_writebyte(outf, 1); // "type"
	dbuf_copy(c->infile, 3, 1, outf); // packing method

	dbuf_writeu32le(outf, zctx->outf_trailer_pos);
	dbuf_writeu32le(outf, zctx->outf_cmpr_pos);

	// date, time, crc, sizeorig, sizenow, maj ver, min ver
	dbuf_copy(c->infile, 4, 16, outf);

	dbuf_writebyte(outf, 0); // "deleted" flag
	dbuf_writebyte(outf, 0); // file structure / reserved
	dbuf_writeu32le(outf, zctx->comment_len?zctx->outf_comment_pos:0);
	dbuf_writeu16le(outf, zctx->comment_len);
	dbuf_copy(c->infile, 22, 13, outf); // filename
	dbuf_writebyte(outf, 0x4f); // ??? This seems to be what Zoo does

	dbuf_write(outf, (const u8*)"@)#(\0", 5); // leader
	dbuf_copy(c->infile, zctx->inf_cmpr_pos, zctx->cmpr_len, outf); // cmpr data

	if(zctx->comment_len) {
		dbuf_copy(c->infile, zctx->inf_comment_pos, zctx->comment_len, outf);
	}

	dbuf_writeu32le(outf, ZOO_SIGNATURE);
	dbuf_write_zeroes(outf, 48);
	need_errmsg = 0;

done:
	dbuf_close(outf);
	if(need_errmsg) {
		de_err(c, "Conversion to Zoo format failed");
	}
	de_free(c, zctx);
}

static int de_identify_zoo_z(deark *c)
{
	if(dbuf_memcmp(c->infile, 0, "\xfe\x07\x01", 3)) return 0;
	return 80;
}

void de_module_zoo_z(deark *c, struct deark_module_info *mi)
{
	mi->id = "zoo_z";
	mi->desc = "Zoo Z format";
	mi->run_fn = de_run_zoo_z;
	mi->identify_fn = de_identify_zoo_z;
}
