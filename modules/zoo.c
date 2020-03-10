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

#define ZOO_SIGNATURE  0xfdc4a7dcU

#define ZOOCMPR_STORED  0
#define ZOOCMPR_LZD     1
#define ZOOCMPR_LZH     2

struct localctx_struct;
typedef struct localctx_struct lctx;
struct member_data;

// Data associated with one ZOO member file
struct member_data {
	de_finfo *fi;
	de_ucstring *fullname;
	u8             type;           /* type of current member (1)      */
	u8             method;         /* packing method of member (0..2) */
	i64 next_member_hdr_pos;
	i64 cmpr_pos;
	i64 cmpr_len;
	i64 uncmpr_len;
	i64 comment_pos; // 0 if no comment
	i64 comment_len;
	unsigned int datdos;         /* date (in DOS format)            */
	unsigned int timdos;         /* time (in DOS format)            */
	u32 crc_reported;
	u32 crc_calculated;
	u32 crc_hdr_reported;
	u8             majver;         /* major version needed to extract */
	u8             minver;         /* minor version needed to extract */
	u8 is_deleted;        /* 1 if member is deleted, 0 else  */
	u8             timzon;         /* time zone                       */
	unsigned int system;         /* system identifier               */
	u32           permis;         /* file permissions                */
	u8             modgen;         /* gens. on, last gen., gen. limit */
	unsigned int ver;            /* version number of member        */
};

struct localctx_struct {
	int input_encoding;
	struct de_inthashtable *offsets_seen;

	i64 first_member_hdr_pos;
	u8             majver;         /* major version needed to extract */
	u8             minver;         /* minor version needed to extract */
	u8             type;  // header version (?)
	i64 archive_comment_pos; // 0 if no comment
	i64 archive_comment_len;
	u8             modgen;         /* gens. on, gen. limit            */

	// Shared by all member files, so we don't have to recalculate the CRC table
	// for each member file.
	struct de_crcobj *crco;
};

static const char *get_member_name_for_msg(deark *c, lctx *d, struct member_data *md)
{
	if(md && ucstring_isnonempty(md->fullname)) {
		return ucstring_getpsz_d(md->fullname);
	}
	return "(?)";
}

static void do_extract_comment(deark *c, lctx *d, i64 pos, i64 len, int is_main)
{
	dbuf_create_file_from_slice(c->infile, pos, len, "comment.txt",
		NULL, DE_CREATEFLAG_IS_AUX);
}

static void do_dbg_comment(deark *c, lctx *d, i64 pos, i64 len, int is_main)
{
	de_ucstring *s = NULL;

	if(c->debug_level<1) return;
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, len, DE_DBG_MAX_STRLEN, s,
		0, d->input_encoding);
	de_dbg(c, "%scomment: \"%s\"", is_main?"(global) ":"",
		ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static void do_comment(deark *c, lctx *d, i64 pos, i64 len, int is_main)
{
	if(len<1) return;
	if(pos<0 || pos+len>c->infile->len) return;
	if(c->extract_level>=2) {
		do_extract_comment(c, d, pos, len, is_main);
	}
	else {
		do_dbg_comment(c, d, pos, len, is_main);
	}
}

// Read the main file header
static int do_global_header(deark *c, lctx *d, i64 pos1)
{
	i64 pos = pos1;
	int retval = 0;
	unsigned int sig;
	unsigned int u;

	de_dbg(c, "header at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	// Skip the text at the start of the file, e.g. "ZOO 2.10 Archive"
	pos += 20;

	sig = (unsigned int)de_getu32le_p(&pos);
	if (sig != ZOO_SIGNATURE) goto done;

	d->first_member_hdr_pos = de_getu32le_p(&pos);
	de_dbg(c, "first entry pos: %"I64_FMT, d->first_member_hdr_pos);

	u = (unsigned int)de_getu32le_p(&pos);
	de_dbg(c, "2's complement of pos: %u (%d)", u, (int)u);
	d->majver = de_getbyte_p(&pos);
	d->minver = de_getbyte_p(&pos);
	de_dbg(c, "(global) version needed to extract: %d.%d", (int)d->majver, (int)d->minver);

	// Fields that aren't present in old versions.
	// Apparently, we have to infer their presence, based on the location of the first
	// member file header.
	if(d->first_member_hdr_pos > 34) {
		d->type = de_getbyte_p(&pos);
		de_dbg(c, "(global) type: %u", (unsigned int)d->type);

		d->archive_comment_pos = de_getu32le_p(&pos);
		d->archive_comment_len = de_getu16le_p(&pos);
		de_dbg(c, "(global) comment: pos=%"I64_FMT", size=%d", d->archive_comment_pos,
			(int)d->archive_comment_len);
		do_comment(c, d, d->archive_comment_pos, d->archive_comment_len, 1);

		d->modgen = de_getbyte_p(&pos);
		de_dbg2(c, "(global) modgen: %u", (unsigned int)d->modgen);
	}

	retval = 1;

done:
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
	int has_ext_header;
	char namebuf[80];

	sig = (unsigned int)de_getu32le_p(&pos);
	if(sig != ZOO_SIGNATURE) {
		de_err(c, "Malformed ZOO file, bad magic number at %"I64_FMT, pos1);
		goto done;
	}

	/* read the fixed part of the directory entry                          */
	md->type   = de_getbyte_p(&pos);
	has_ext_header = (md->type == 2);
	md->method = de_getbyte_p(&pos);
	md->next_member_hdr_pos = de_getu32le_p(&pos);

	if(md->next_member_hdr_pos == 0) {
		// I guess that end of file is marked by a dummy member file entry
		// having next_member_hdr_pos=0.
		de_dbg(c, "next entry pos: %d (eof)", (int)md->next_member_hdr_pos);
		retval = 1;
		goto done;
	}

	de_dbg(c, "type: %d", (int)md->type);
	de_dbg(c, "compression method: %d (%s)", (int)md->method, get_cmpr_meth_name(md->method));
	de_dbg(c, "next entry pos: %"I64_FMT, md->next_member_hdr_pos);

	md->cmpr_pos = de_getu32le_p(&pos);
	de_dbg(c, "pos of file data: %"I64_FMT, md->cmpr_pos);

	md->datdos = (unsigned int)de_getu16le_p(&pos);
	md->timdos = (unsigned int)de_getu16le_p(&pos);
	de_dbg2(c, "dos date,time: %u,%u", md->datdos, md->timdos);
	if(!has_ext_header) {
		md->timzon = 127;
		finish_modtime_decoding(c, d, md);
	}

	md->crc_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "file data crc (reported): 0x%04x", (unsigned int)md->crc_reported);
	md->uncmpr_len = de_getu32le_p(&pos);
	de_dbg(c, "original size: %"I64_FMT, md->uncmpr_len);
	md->cmpr_len = de_getu32le_p(&pos);
	de_dbg(c, "compressed size: %"I64_FMT, md->cmpr_len);
	md->majver = de_getbyte_p(&pos);
	md->minver = de_getbyte_p(&pos);
	de_dbg(c, "version needed to extract: %d.%d", (int)md->majver, (int)md->minver);
	md->is_deleted = de_getbyte_p(&pos);
	de_dbg(c, "is deleted: %d", (int)md->is_deleted);
	pos++; // "file structure" (?)
	md->comment_pos = de_getu32le_p(&pos);
	md->comment_len = de_getu16le_p(&pos);
	de_dbg(c, "comment: pos=%"I64_FMT", size=%d", md->comment_pos, (int)md->comment_len);
	if((md->next_member_hdr_pos!=0) && (md->is_deleted != 1)) {
		do_comment(c, d, md->comment_pos, md->comment_len, 0);
	}

	shortname = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 13, shortname, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "short name: \"%s\"", ucstring_getpsz(shortname));
	pos += 13;

	if(!has_ext_header) {
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
		de_strlcpy(namebuf, "unknown", sizeof(namebuf));
	}
	else if(md->timzon>127) {
		de_snprintf(namebuf, sizeof(namebuf), "%.2f hours east of UTC",
			((double)md->timzon - 256.0)/-4.0);
	}
	else {
		de_snprintf(namebuf, sizeof(namebuf), "%.2f hours west of UTC",
			((double)md->timzon)/4.0);
	}
	de_dbg(c, "time zone: %d (%s)", (int)md->timzon, namebuf);
	finish_modtime_decoding(c, d, md);

	md->crc_hdr_reported = (u32)de_getu16le_p(&pos);
	de_dbg(c, "entry crc (reported): 0x%04x", (unsigned int)md->crc_hdr_reported);

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
	md->permis = (u32)dbuf_getint_ext(c->infile, pos, 3, 1, 0);
	pos += 3;
	de_dbg(c, "perms: octal(%o)", (unsigned int)md->permis);
	if((md->permis & 0111) != 0) {
		md->fi->mode_flags |= DE_MODEFLAG_EXE;
	}
	else {
		md->fi->mode_flags |= DE_MODEFLAG_NONEXE;
	}

	if(hdr_endpos-pos < 1) goto done_with_header;
	md->modgen = de_getbyte_p(&pos);
	de_dbg(c, "modgen: %u", (unsigned int)md->modgen);

	if(hdr_endpos-pos < 2) goto done_with_header;
	md->ver = (unsigned int)de_getu16le_p(&pos);
	de_dbg(c, "member version: %u", md->ver);

done_with_header:
	// Note: Typically, there is a 5-byte "file leader" ("@)#(\0") here, between
	// the member header and the member data, so pos is not
	// expected to equal md->posdat.

	// Figure out the best filename to use
	if(ucstring_isnonempty(longname) || ucstring_isnonempty(shortname)) {
		if(ucstring_isnonempty(dirname)) {
			ucstring_append_ucstring(md->fullname, dirname);
			ucstring_append_sz(md->fullname, "/", DE_ENCODING_ASCII);
		}
		if(ucstring_isnonempty(longname)) {
			ucstring_append_ucstring(md->fullname, longname);
		}
		else if(ucstring_isnonempty(shortname)) {
			ucstring_append_ucstring(md->fullname, shortname);
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

static void our_writelistener_cb(dbuf *f, void *userdata, const u8 *buf, i64 buf_len)
{
	struct de_crcobj *crco = (struct de_crcobj *)userdata;

	de_crcobj_addbuf(crco, buf, buf_len);
}

// Process a single member file (or EOF marker).
// If there are more members after this, sets *next_member_hdr_pos to nonzero.
static void do_member(deark *c, lctx *d, i64 pos1, i64 *next_member_hdr_pos)
{
	struct member_data *md = NULL;
	dbuf *outf = NULL;
	const char *ext;
	struct de_dfilter_in_params dcmpri;
	struct de_dfilter_out_params dcmpro;
	struct de_dfilter_results dres;

	de_dfilter_init_objects(c, &dcmpri, &dcmpro, &dres);

	md = de_malloc(c, sizeof(struct member_data));
	md->fi = de_finfo_create(c);
	md->fullname = ucstring_create(c);

	if (!do_member_header(c, d, md, pos1)) {
		goto done;
	}

	*next_member_hdr_pos = md->next_member_hdr_pos;

	if ( ! md->next_member_hdr_pos ) {
		goto done;
	}

	if(md->is_deleted == 1) {
		de_dbg(c, "ignoring deleted entry");
		goto done;
	}

	if ( (md->majver>2) || (md->majver==2 && md->minver>1) ) {
		de_err(c, "Unsupported format version: %d.%d",
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
	dbuf_set_writelistener(outf, our_writelistener_cb, (void*)d->crco);
	de_crcobj_reset(d->crco);

	dcmpri.f = c->infile;
	dcmpri.pos = md->cmpr_pos;
	dcmpri.len = md->cmpr_len;

	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = md->uncmpr_len;

	switch(md->method) {
	case ZOOCMPR_STORED:
		fmtutil_decompress_uncompressed(c, &dcmpri, &dcmpro, &dres, 0);
		break;
	case ZOOCMPR_LZD:
		de_fmtutil_decompress_zoo_lzd(c, &dcmpri, &dcmpro, &dres, 13);
		break;
	case ZOOCMPR_LZH:
		de_fmtutil_decompress_zoo_lzh(c, &dcmpri, &dcmpro, &dres);
		break;
	default:
		goto done; // Should be impossible
	}

	md->crc_calculated = de_crcobj_getval(d->crco);
	de_dbg(c, "file data crc (calculated): 0x%04x", (unsigned int)md->crc_calculated);

	if(dres.errcode) {
		de_err(c, "%s: %s", get_member_name_for_msg(c, d, md),
			de_dfilter_get_errmsg(c, &dres));
	}
	else if(outf->len != md->uncmpr_len) {
		de_err(c, "%s: Expected %"I64_FMT" uncompressed bytes, got %"I64_FMT,
			get_member_name_for_msg(c, d, md), md->uncmpr_len, outf->len);
	}
	else if (md->crc_calculated != md->crc_reported) {
		de_err(c, "%s: CRC failed", get_member_name_for_msg(c, d, md));
	}

done:
	dbuf_close(outf);
	if(md) {
		ucstring_destroy(md->fullname);
		de_finfo_destroy(c, md->fi);
		de_free(c, md);
	}
}

// The main function: process a ZOO file
static void de_run_zoo(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos = 0;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(lctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_ASCII);

	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);

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
			goto done;
		}

		if(!de_inthashtable_add_item(c, d->offsets_seen, pos, NULL)) {
			de_err(c, "Loop detected");
			goto done;
		}

		de_dbg(c, "entry at %"I64_FMT, pos);
		de_dbg_indent(c, 1);

		next_member_hdr_pos = 0;
		do_member(c, d, pos, &next_member_hdr_pos);
		pos = next_member_hdr_pos;
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

void de_module_zoo(deark *c, struct deark_module_info *mi)
{
	mi->id = "zoo";
	mi->desc = "ZOO compressed archive format";
	mi->run_fn = de_run_zoo;
	mi->identify_fn = de_identify_zoo;
}
