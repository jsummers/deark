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

// Data associated with one ZOO file Entry
struct member_data {
	de_finfo *fi;
	u32 crc_calculated;

	u8             type;           /* type of current member (1)      */
	u8             method;         /* packing method of member (0..2) */
	i64           posnxt;         /* position of next member         */
	i64           posdat;         /* position of data                */
	unsigned int datdos;         /* date (in DOS format)            */
	unsigned int timdos;         /* time (in DOS format)            */
	u32           crcdat;         /* crc value of member             */
	i64           sizorg;         /* uncompressed size of member     */
	i64           siznow;         /*   compressed size of member     */
	u8             majver;         /* major version needed to extract */
	u8             minver;         /* minor version needed to extract */
	u8 is_deleted;        /* 1 if member is deleted, 0 else  */
	i64           poscmt;         /* position of comment, 0 if none  */
	i64 sizcmt;         /* length   of comment, 0 if none  */
	i64 lvar;           /* length of variable part         */
	u8             timzon;         /* time zone                       */
	u32           crcent;         /* crc value of entry              */
	i64 lnamu;          /* length of long name             */
	i64 ldiru;          /* length of directory             */
	unsigned int system;         /* system identifier               */
	u32           permis;         /* file permissions                */
	u8             modgen;         /* gens. on, last gen., gen. limit */
	unsigned int ver;            /* version number of member        */

	de_ucstring *fullname_ucstring;
};

struct localctx_struct {
	int input_encoding;
	struct de_inthashtable *offsets_seen;

	i64 first_dirent_pos; /* position of first directory ent.*/
	u8             majver;         /* major version needed to extract */
	u8             minver;         /* minor version needed to extract */
	u8             type;  // header version (?)
	i64           poscmt;         /* position of comment, 0 if none  */
	i64 sizcmt;         /* length   of comment, 0 if none  */
	u8             modgen;         /* gens. on, gen. limit            */

	// Shared by all member files, so we don't have to recalculate the CRC table
	// for each member file.
	struct de_crcobj *crco;
};

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

	de_dbg(c, "header at %d", 0);
	de_dbg_indent(c, 1);

	/* the text at the beginning                                      */
	pos += 20;

	sig = (unsigned int)de_getu32le_p(&pos);
	if (sig != ZOO_SIGNATURE) goto done;

	/* read the old part of the description                                */
	d->first_dirent_pos = de_getu32le_p(&pos);
	de_dbg(c, "first entry pos: %"I64_FMT, d->first_dirent_pos);

	u = (unsigned int)de_getu32le_p(&pos);
	de_dbg(c, "2's complement of pos: %u (%d)", u, (int)u);
	d->majver = de_getbyte_p(&pos);
	d->minver = de_getbyte_p(&pos);
	de_dbg(c, "(global) version needed to extract: %d.%d", (int)d->majver, (int)d->minver);

	/* read the new part of the description if present                     */
	if(d->first_dirent_pos > 34) {
		d->type = de_getbyte_p(&pos);
		de_dbg(c, "(global) type: %u", (unsigned int)d->type);

		d->poscmt = de_getu32le_p(&pos);
		d->sizcmt = de_getu16le_p(&pos);
		de_dbg(c, "(global) comment: pos=%"I64_FMT", size=%d", d->poscmt, (int)d->sizcmt);
		do_comment(c, d, d->poscmt, d->sizcmt, 1);

		d->modgen = de_getbyte_p(&pos);
		de_dbg2(c, "(global) modgen: %u", (unsigned int)d->modgen);
	}
	else {
		d->type   = 0;
		d->poscmt = 0;
		d->sizcmt = 0;
		d->modgen = 0;
	}

	/* indicate success                                                    */
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

static int do_member_header(deark *c, lctx *d, struct member_data *md, i64 pos1)
{
	i64 l;              /* 'Entry.lnamu+Entry.ldiru'       */
	de_ucstring *shortname_ucstring = NULL;
	de_ucstring *longname_ucstring = NULL;
	de_ucstring *dirname_ucstring = NULL;
	int retval = 0;
	i64 pos = pos1;
	unsigned int sig;
	i64 timestamp_offset;
	char timestamp_buf[64];

	sig = (unsigned int)de_getu32le_p(&pos);
	if(sig != ZOO_SIGNATURE) {
		de_err(c, "Malformed ZOO file, bad magic number at %"I64_FMT, pos1);
		goto done;
	}

	/* read the fixed part of the directory entry                          */
	md->type   = de_getbyte_p(&pos);
	md->method = de_getbyte_p(&pos);
	md->posnxt = de_getu32le_p(&pos);

	if(md->posnxt == 0) {
		// I guess that end of file is marked by a dummy member file entry
		// having posnxt=0.
		de_dbg(c, "next entry pos: %d (eof)", (int)md->posnxt);
		retval = 1;
		goto done;
	}

	de_dbg(c, "type: %d", (int)md->type);
	de_dbg(c, "compression method: %d (%s)", (int)md->method, get_cmpr_meth_name(md->method));
	de_dbg(c, "next entry pos: %"I64_FMT, md->posnxt);

	md->posdat = de_getu32le_p(&pos);
	de_dbg(c, "pos of file data: %"I64_FMT, md->posdat);

	md->datdos = (unsigned int)de_getu16le_p(&pos);
	md->timdos = (unsigned int)de_getu16le_p(&pos);
	de_dbg2(c, "dos date,time: %u,%u", md->datdos, md->timdos);
	md->crcdat = (u32)de_getu16le_p(&pos);
	de_dbg(c, "file data crc (reported): 0x%04x", (unsigned int)md->crcdat);
	md->sizorg = de_getu32le_p(&pos);
	de_dbg(c, "original size: %"I64_FMT, md->sizorg);
	md->siznow = de_getu32le_p(&pos);
	de_dbg(c, "compressed size: %"I64_FMT, md->siznow);
	md->majver = de_getbyte_p(&pos);
	md->minver = de_getbyte_p(&pos);
	de_dbg(c, "version needed to extract: %d.%d", (int)md->majver, (int)md->minver);
	md->is_deleted = de_getbyte_p(&pos);
	de_dbg(c, "is deleted: %d", (int)md->is_deleted);
	pos++; // "file structure" (?)
	md->poscmt = de_getu32le_p(&pos);
	md->sizcmt = de_getu16le_p(&pos);
	de_dbg(c, "comment: pos=%"I64_FMT", size=%d", md->poscmt, (int)md->sizcmt);
	if((md->posnxt!=0) && (md->is_deleted != 1)) {
		do_comment(c, d, md->poscmt, md->sizcmt, 0);
	}

	shortname_ucstring = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 13, shortname_ucstring, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "short name: \"%s\"", ucstring_getpsz(shortname_ucstring));
	pos += 13;

	/* handle the long name and the directory in the variable part         */

	if(md->type == 2) {
		md->lvar   = de_getu16le_p(&pos);
		de_dbg(c, "length of variable part: %d", (int)md->lvar);
	}
	else {
		md->lvar   = 0;
	}

	if(md->type == 2) {
		char namebuf[80];

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

	}
	else {
		md->timzon = 127;
	}

	// Now that we know the timezone, finish reporting the mod time, and set
	// md->fi->mod_time.
	timestamp_offset = 0;
	if      ( md->timzon < 127 )  timestamp_offset = 15*60*((i64)md->timzon      );
	else if ( 127 < md->timzon )  timestamp_offset = 15*60*((i64)md->timzon - 256);

	de_dos_datetime_to_timestamp(&md->fi->mod_time, (i64)md->datdos, (i64)md->timdos);
	de_timestamp_to_string(&md->fi->mod_time, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "mod time: %s", timestamp_buf);
	if(md->timzon == 127) {
		md->fi->mod_time.tzcode = DE_TZCODE_LOCAL;
	}
	else {
		de_timestamp_cvt_to_utc(&md->fi->mod_time, timestamp_offset);
		de_timestamp_to_string(&md->fi->mod_time, timestamp_buf, sizeof(timestamp_buf), 0);
		de_dbg(c, "mod time (UTC): %s", timestamp_buf);
	}

	if(md->type == 2) {
		md->crcent = (u32)de_getu16le_p(&pos);
		de_dbg(c, "entry crc (reported): 0x%04x", (unsigned int)md->crcent);
	}
	else {
		md->crcent = 0;
	}

	if(md->lvar > 0) {
		md->lnamu = (i64)de_getbyte_p(&pos);
		de_dbg2(c, "long name len: %d", (int)md->lnamu);
	}
	else {
		md->lnamu = 0;
	}

	if(md->lvar > 1) {
		md->ldiru = (i64)de_getbyte_p(&pos);
		de_dbg2(c, "dir name len: %d", (int)md->ldiru);
	}
	else {
		md->ldiru = 0;
	}

	longname_ucstring = ucstring_create(c);
	if(md->lnamu>0) {
		dbuf_read_to_ucstring(c->infile, pos, md->lnamu, longname_ucstring,
			DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
		de_dbg(c, "long name: \"%s\"", ucstring_getpsz(longname_ucstring));
	}
	pos += md->lnamu;

	dirname_ucstring = ucstring_create(c);
	if(md->ldiru>0) {
		dbuf_read_to_ucstring(c->infile, pos, md->ldiru, dirname_ucstring,
			DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
		de_dbg(c, "dir name: \"%s\"", ucstring_getpsz(dirname_ucstring));
	}
	pos += md->ldiru;

	l = md->lnamu + md->ldiru;
	if(l+2 < md->lvar) {
		md->system = (unsigned int)de_getu16le_p(&pos);
		de_dbg(c, "system id: %u", md->system);
	}
	else {
		md->system = 0;
	}

	if(l+4 < md->lvar) {
		md->permis = (u32)dbuf_getint_ext(c->infile, pos, 3, 1, 0);
		pos += 3;
	}
	else {
		md->permis = 0;
	}
	if(l+4 < md->lvar) {
		de_dbg(c, "perms: octal(%o)", (unsigned int)md->permis);
		if((md->permis & 0111) != 0) {
			md->fi->mode_flags |= DE_MODEFLAG_EXE;
		}
		else {
			md->fi->mode_flags |= DE_MODEFLAG_NONEXE;
		}
	}

	if(l+7 < md->lvar) {
		md->modgen = de_getbyte_p(&pos);
		de_dbg(c, "modgen: %u", (unsigned int)md->modgen);
	}
	else {
		md->modgen = 0;
	}

	if(l+9 < md->lvar) {
		md->ver = (unsigned int)de_getu16le_p(&pos);
		de_dbg(c, "member version: %u", md->ver);
	}
	else {
		md->ver = 0;
	}

	// Note: Typically, there is a 5-byte "file leader" ("@)#(\0") here, between
	// the member header and the member data, so pos is not
	// expected to equal md->posdat.

	// Figure out the best filename to use
	if(ucstring_isnonempty(longname_ucstring) || ucstring_isnonempty(shortname_ucstring)) {
		if(ucstring_isnonempty(dirname_ucstring)) {
			ucstring_append_ucstring(md->fullname_ucstring, dirname_ucstring);
			ucstring_append_sz(md->fullname_ucstring, "/", DE_ENCODING_ASCII);
		}
		if(ucstring_isnonempty(longname_ucstring)) {
			ucstring_append_ucstring(md->fullname_ucstring, longname_ucstring);
		}
		else if(ucstring_isnonempty(shortname_ucstring)) {
			ucstring_append_ucstring(md->fullname_ucstring, shortname_ucstring);
		}

		de_finfo_set_name_from_ucstring(c, md->fi, md->fullname_ucstring, DE_SNFLAG_FULLPATH);
		md->fi->original_filename_flag = 1;
	}

	retval = 1;

done:
	ucstring_destroy(shortname_ucstring);
	ucstring_destroy(longname_ucstring);
	ucstring_destroy(dirname_ucstring);
	return retval;
}

static void our_writecallback(dbuf *f, const u8 *buf, i64 buf_len)
{
	struct de_crcobj *crco = (struct de_crcobj *)f->userdata;

	de_crcobj_addbuf(crco, buf, buf_len);
}

/****************************************************************************
**
*F  DecodeCopy(<size>). . . . . . . . . . . .  extract an uncompressed member
**
**  'DecodeCopy' simply  copies <size> bytes  from the  archive to the output
**  file.
*/
static void DecodeCopy (deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	dbuf_copy(dcmpri->f, dcmpri->pos, dcmpri->len, dcmpro->f);
}

// Process a single member file
static void do_member(deark *c, lctx *d, i64 pos1, i64 *next_entry_pos)
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
	md->fullname_ucstring = ucstring_create(c);

	/* read the directory entry for the next member                    */
	if (!do_member_header(c, d, md, pos1)) {
		de_err(c, "Found bad directory entry in archive");
		goto done;
	}

	*next_entry_pos = md->posnxt;

	if ( ! md->posnxt ) {
		goto done;
	}

	/* skip members we don't care about                                */
	if(md->is_deleted == 1) {
		de_dbg(c, "ignoring deleted entry");
		goto done;
	}

	/* check that we can decode this file                              */
	if ( (2 < md->majver) || (2 == md->majver && 1 < md->minver) ) {
		de_err(c, "Unsupported format version: %d.%d",
			(int)md->majver, (int)md->minver);
		goto done;
	}

	if(md->method!=ZOOCMPR_STORED && md->method!=ZOOCMPR_LZD && md->method!=ZOOCMPR_LZH) {
		de_err(c, "Unsupported compression method: %d", (int)md->method);
		goto done;
	}

	de_dbg(c, "compressed data at %"I64_FMT", len=%"I64_FMT, md->posdat,
		md->siznow);

	if(md->posdat + md->siznow > c->infile->len) {
		de_err(c, "Unexpected <eof> in the archive");
		goto done;
	}

	// Set up the output file
	if(md->fi && md->fi->original_filename_flag) {
		ext = NULL;
	}
	else {
		ext = "bin";
	}
	outf = dbuf_create_output_file(c, ext, md->fi, 0);
	outf->writecallback_fn = our_writecallback;
	outf->userdata = (void*)d->crco;
	de_crcobj_reset(d->crco);

	dcmpri.f = c->infile;
	dcmpri.pos = md->posdat;
	dcmpri.len = md->siznow;

	dcmpro.f = outf;
	dcmpro.len_known = 1;
	dcmpro.expected_len = md->sizorg;

	switch(md->method) {
	case ZOOCMPR_STORED:
		DecodeCopy(c, &dcmpri, &dcmpro, &dres);
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

	/* check that everything went ok                                   */
	if(dres.errcode) {
		de_err(c, "%s", de_dfilter_get_errmsg(c, &dres));
	}
	else if(outf->len != md->sizorg) {
		de_err(c, "Expected %"I64_FMT" uncompressed bytes, got %"I64_FMT,
			md->sizorg, outf->len);
	}
	else if ( md->crc_calculated != md->crcdat ) {
		de_err(c, "CRC failed");
	}

done:
	dbuf_close(outf);
	if(md) {
		ucstring_destroy(md->fullname_ucstring);
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
	d->input_encoding = DE_ENCODING_ASCII;

	d->crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_ARC);

	if(!do_global_header(c, d, pos)) {
		de_err(c, "Found bad description in archive");
		goto done;
	}

	/* loop over the members of the archive                                */
	d->offsets_seen = de_inthashtable_create(c); // For protection against infinite loops
	pos = d->first_dirent_pos;
	while ( 1 ) {
		i64 next_entry_pos;

		de_dbg_indent_restore(c, saved_indent_level);

		if(pos==0) break;

		if(pos >= c->infile->len) {
			de_err(c, "Unexpected EOF");
			goto done;
		}

		if(!de_inthashtable_add_item(c, d->offsets_seen, pos, NULL)) {
			de_err(c, "Loop detected");
			goto done;
		}

		de_dbg(c, "entry at %d", (int)pos);
		de_dbg_indent(c, 1);

		next_entry_pos = 0;
		do_member(c, d, pos, &next_entry_pos);
		pos = next_entry_pos;
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
