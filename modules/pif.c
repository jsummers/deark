// This file is part of Deark.
// Copyright (C) 2022 Jason Summers
// See the file COPYING for terms of use.

// Windows Program Information File (.PIF)
// DESQview Program Information File (.DVP)

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_pif);
DE_DECLARE_MODULE(de_module_desqview_dvp);

#define PIF_BASIC_SECTION_SIZE 369
#define PIF_INVALID_HEADING_POS 0xffff

struct pif_ctx {
	de_encoding input_encoding_oem;
	de_encoding input_encoding_ansi;
	de_ucstring *tmpstr;
	i64 next_section_heading_pos;
	struct de_inthashtable *pos_seen;
	UI checksum_calc;
};

static int pif_validate_pos(deark *c, struct pif_ctx *d, i64 pos)
{
	if(de_inthashtable_add_item(c, d->pos_seen, pos, NULL)) {
		return 1;
	}
	de_err(c, "Bad offset detected");
	return 0;
}

static void do_pif_section_extract(deark *c, struct pif_ctx *d, i64 pos1, i64 len, const char *name)
{
	dbuf_create_file_from_slice(c->infile, pos1, len, name, NULL, 0);
}

static void do_pif_section_default(deark *c, struct pif_ctx *d, i64 pos1, i64 len)
{
	de_dbg_hexdump(c, c->infile, pos1, len, 256, NULL, 0x1);
}

static int cksum_cbfn(struct de_bufferedreadctx *brctx, const u8 *buf,
	i64 buf_len)
{
	i64 i;
	struct pif_ctx *d = (struct pif_ctx*)brctx->userdata;

	for(i=0; i<buf_len; i++) {
		d->checksum_calc += (UI)buf[i];
	}
	d->checksum_calc &= 0xff;
	return 1;
}

// Sets d->checksum_calc
static void pif_calc_checksum(deark *c, struct pif_ctx *d)
{
	d->checksum_calc = 0;
	dbuf_buffered_read(c->infile, 2, PIF_BASIC_SECTION_SIZE-2, cksum_cbfn, (void*)d);
}

static void do_pif_section_basic(deark *c, struct pif_ctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;
	i64 n;
	UI checksum_reported;

	pos++; // unused

	checksum_reported = (UI)de_getbyte_p(&pos);
	de_dbg(c, "checksum (reported): 0x%02x", checksum_reported);
	pif_calc_checksum(c, d);
	// Note - Not all files set the checksum field. Often it's just set to 0x78,
	// but other wrong values are common.
	de_dbg(c, "checksum (calculated): 0x%02x", d->checksum_calc);

	ucstring_empty(d->tmpstr);
	dbuf_read_to_ucstring(c->infile, pos, 30, d->tmpstr, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding_oem);
	ucstring_strip_trailing_spaces(d->tmpstr);
	de_dbg(c, "title: \"%s\"", ucstring_getpsz_d(d->tmpstr));
	pos += 30;

	n = de_getu16le_p(&pos);
	de_dbg(c, "max conventional mem: %"I64_FMT" kb", n);
	n = de_getu16le_p(&pos);
	de_dbg(c, "min conventional mem: %"I64_FMT" kb", n);

	ucstring_empty(d->tmpstr);
	dbuf_read_to_ucstring(c->infile, pos, 63, d->tmpstr, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding_oem);
	ucstring_strip_trailing_spaces(d->tmpstr);
	de_dbg(c, "target filename: \"%s\"", ucstring_getpsz_d(d->tmpstr));
	pos += 63;

	// TODO: There's disagreement about what the next 2 bytes are.
	n = de_getu16le_p(&pos);
	de_dbg(c, "flags1: 0x%04x", (UI)n);

	ucstring_empty(d->tmpstr);
	dbuf_read_to_ucstring(c->infile, pos, 64, d->tmpstr, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding_oem);
	ucstring_strip_trailing_spaces(d->tmpstr);
	de_dbg(c, "work dir: \"%s\"", ucstring_getpsz_d(d->tmpstr));
	pos += 64;

	ucstring_empty(d->tmpstr);
	dbuf_read_to_ucstring(c->infile, pos, 64, d->tmpstr, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding_oem);
	ucstring_strip_trailing_spaces(d->tmpstr);
	de_dbg(c, "params: \"%s\"", ucstring_getpsz_d(d->tmpstr));
	pos += 64;

	// TODO: More fields
}

static void do_pif_section_win286(deark *c, struct pif_ctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;
	i64 n;
	UI flags;

	if(len<6) return;
	n = de_getu16le_p(&pos);
	de_dbg(c, "max XMS: %"I64_FMT, n);
	n = de_getu16le_p(&pos);
	de_dbg(c, "min XMS: %"I64_FMT, n);
	flags = (UI)de_getu16le_p(&pos);
	de_dbg(c, "flags: 0x%04x", (UI)flags);
}

static void do_pif_section_win386(deark *c, struct pif_ctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;
	i64 n;
	UI flags;

	if(len<104) return;
	n = de_getu16le_p(&pos);
	de_dbg(c, "max conventional mem: %"I64_FMT, n);
	n = de_getu16le_p(&pos);
	de_dbg(c, "min conventional mem: %"I64_FMT, n);
	pos += 2; // fg priority
	pos += 2; // bg priority
	n = de_getu16le_p(&pos);
	de_dbg(c, "max EMS: %"I64_FMT, n);
	n = de_getu16le_p(&pos);
	de_dbg(c, "min EMS: %"I64_FMT, n);
	n = de_getu16le_p(&pos);
	de_dbg(c, "max XMS: %"I64_FMT, n);
	n = de_getu16le_p(&pos);
	de_dbg(c, "min XMS: %"I64_FMT, n);
	flags = (UI)de_getu32le_p(&pos);
	de_dbg(c, "flags1: 0x%08x", (UI)flags);
	flags = (UI)de_getu16le_p(&pos);
	de_dbg(c, "flags2: 0x%04x", (UI)flags);

	// TODO: More fields

	pos = pos1 + 40;
	ucstring_empty(d->tmpstr);
	// TODO: There are questions about whether this is OEM or ANSI
	dbuf_read_to_ucstring(c->infile, pos, 64, d->tmpstr, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding_oem);
	ucstring_strip_trailing_spaces(d->tmpstr);
	de_dbg(c, "params: \"%s\"", ucstring_getpsz_d(d->tmpstr));
}

static void do_pif_section_winvmm(deark *c, struct pif_ctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;
	i64 n;

	if(len<428) return;
	pos += 88;

	ucstring_empty(d->tmpstr);
	dbuf_read_to_ucstring(c->infile, pos, 80, d->tmpstr, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding_ansi);
	de_dbg(c, "icon file: \"%s\"", ucstring_getpsz_d(d->tmpstr));
	pos += 80;

	n = de_getu16le_p(&pos);
	de_dbg(c, "icon #: %"I64_FMT, n);

	pos = pos1 + 234;
	ucstring_empty(d->tmpstr);
	dbuf_read_to_ucstring(c->infile, pos, 32, d->tmpstr, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding_ansi);
	de_dbg(c, "raster font: \"%s\"", ucstring_getpsz_d(d->tmpstr));
	pos += 32;

	ucstring_empty(d->tmpstr);
	dbuf_read_to_ucstring(c->infile, pos, 32, d->tmpstr, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding_ansi);
	de_dbg(c, "TrueType font: \"%s\"", ucstring_getpsz_d(d->tmpstr));

	pos = pos1 + 342;
	ucstring_empty(d->tmpstr);
	dbuf_read_to_ucstring(c->infile, pos, 80, d->tmpstr, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding_oem);
	de_dbg(c, "BAT file: \"%s\"", ucstring_getpsz_d(d->tmpstr));

	// TODO: More fields
}

static void do_pif_section_winnt31(deark *c, struct pif_ctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;

	if(len<140) return;
	pos += 12;

	ucstring_empty(d->tmpstr);
	dbuf_read_to_ucstring(c->infile, pos, 64, d->tmpstr, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding_ansi);
	de_dbg(c, "alt config.sys: \"%s\"", ucstring_getpsz_d(d->tmpstr));
	pos += 64;

	ucstring_empty(d->tmpstr);
	dbuf_read_to_ucstring(c->infile, pos, 64, d->tmpstr, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding_ansi);
	de_dbg(c, "alt autoexec.bat: \"%s\"", ucstring_getpsz_d(d->tmpstr));
}

// Returns nonzero if we should look for more sections after this.
// Sets d->next_section_heading_pos.
static int do_pif_section(deark *c, struct pif_ctx *d, i64 pos1)
{
	int saved_indent_level;
	int retval = 0;
	i64 pos = pos1;
	i64 dpos;
	i64 dlen;
	struct de_stringreaderdata *secname = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "section at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	secname = dbuf_read_string(c->infile, pos,
		16, 16, DE_CONVFLAG_STOP_AT_NUL, d->input_encoding_ansi);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(secname->str));
	pos += 16;

	d->next_section_heading_pos = de_getu16le_p(&pos);
	de_dbg(c, "next section pos: %"I64_FMT, d->next_section_heading_pos);
	dpos = de_getu16le_p(&pos);
	de_dbg(c, "data pos: %"I64_FMT, dpos);
	dlen = de_getu16le_p(&pos);
	de_dbg(c, "data len: %"I64_FMT, dlen);
	if(d->next_section_heading_pos != PIF_INVALID_HEADING_POS) {
		retval = 1;
	}

	if(dlen != 0) {
		if(!pif_validate_pos(c, d, dpos)) goto done;
	}

	de_dbg(c, "section data at %"I64_FMT", len=%"I64_FMT, dpos, dlen);
	de_dbg_indent(c, 1);
	if(!de_strcmp(secname->sz, "MICROSOFT PIFEX")) {
		do_pif_section_basic(c, d, dpos, dlen);
	}
	else if(!de_strcmp(secname->sz, "WINDOWS 286 3.0")) {
		do_pif_section_win286(c, d, dpos, dlen);
	}
	else if(!de_strcmp(secname->sz, "WINDOWS 386 3.0")) {
		do_pif_section_win386(c, d, dpos, dlen);
	}
	else if(!de_strcmp(secname->sz, "WINDOWS VMM 4.0")) {
		do_pif_section_winvmm(c, d, dpos, dlen);
	}
	else if(!de_strcmp(secname->sz, "WINDOWS NT  3.1")) {
		do_pif_section_winnt31(c, d, pos, dlen);
	}
	else if(!de_strcmp(secname->sz, "AUTOEXECBAT 4.0")) {
		do_pif_section_extract(c, d, dpos, dlen, "autoexec.bat");
	}
	else if(!de_strcmp(secname->sz, "CONFIG  SYS 4.0")) {
		do_pif_section_extract(c, d, dpos, dlen, "config.sys");
	}
	else {
		do_pif_section_default(c, d, dpos, dlen);
	}
	// TODO:
	//  WINDOWS NT  4.0
	//  WINDOWS PIF.402
	//  WINDOWS PIF.403
	//  WINDOWS ICO.001

done:
	de_destroy_stringreaderdata(c, secname);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void do_pif_sections(deark *c, struct pif_ctx *d)
{
	d->next_section_heading_pos = PIF_BASIC_SECTION_SIZE;

	while(1) {
		i64 this_section_heading_pos;

		this_section_heading_pos = d->next_section_heading_pos;
		if(this_section_heading_pos == PIF_INVALID_HEADING_POS) break;
		d->next_section_heading_pos = PIF_INVALID_HEADING_POS;
		if(this_section_heading_pos+22 > c->infile->len) break;
		if(!pif_validate_pos(c, d, this_section_heading_pos)) break;

		if(!do_pif_section(c, d, this_section_heading_pos)) break;
	}
}

static void do_dvp_extensions(deark *c, struct pif_ctx *d)
{
	i64 pos;
	u8 dvextver;

	pos = PIF_BASIC_SECTION_SIZE;
	ucstring_empty(d->tmpstr);
	dbuf_read_to_ucstring(c->infile, pos, 2, d->tmpstr, 0, DE_ENCODING_ASCII);
	de_dbg(c, "keys: \"%s\"", ucstring_getpsz_d(d->tmpstr));

	pos = PIF_BASIC_SECTION_SIZE + 13;
	dvextver = de_getbyte(pos);
	de_dbg(c, "DV extensions ver: %u", (UI)dvextver);
}

static void do_pif_main(deark *c, de_module_params *mparams, int is_dvp)
{
	const char *tmps;
	struct pif_ctx *d = NULL;
	int is_oldfmt = 0;

	d = de_malloc(c, sizeof(struct pif_ctx));
	d->tmpstr = ucstring_create(c);

	d->input_encoding_ansi = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);

	d->input_encoding_oem = DE_ENCODING_CP437; // default
	tmps = de_get_ext_option(c, "oemenc");
	if(tmps) {
		d->input_encoding_oem = de_encoding_name_to_code(tmps);
		if(d->input_encoding_oem == DE_ENCODING_UNKNOWN) {
			d->input_encoding_oem = DE_ENCODING_CP437;
		}
	}

	d->pos_seen = de_inthashtable_create(c);

	if(!is_dvp && (c->infile->len < PIF_BASIC_SECTION_SIZE+22)) {
		is_oldfmt = 1;
	}

	if(is_oldfmt) {
		do_pif_section_basic(c, d, 0, PIF_BASIC_SECTION_SIZE);
	}
	else if(is_dvp) {
		do_pif_section_basic(c, d, 0, PIF_BASIC_SECTION_SIZE);
		do_dvp_extensions(c, d);
	}
	else {
		do_pif_sections(c, d);
	}

	if(d) {
		ucstring_destroy(d->tmpstr);
		de_inthashtable_destroy(c, d->pos_seen);
		de_free(c, d);
	}
}

static void de_run_pif(deark *c, de_module_params *mparams)
{
	do_pif_main(c, mparams, 0);
}

static int de_identify_pif(deark *c)
{
	int maybe_oldfmt = 0;
	int has_id = 0;
	int has_ext;

	if(c->infile->len == PIF_BASIC_SECTION_SIZE) {
		maybe_oldfmt = 1;
	}
	else if(c->infile->len >= PIF_BASIC_SECTION_SIZE+22) {
		has_id = !dbuf_memcmp(c->infile, PIF_BASIC_SECTION_SIZE,
			(const u8*)"MICROSOFT PIFEX\0", 16);
	}

	if(!maybe_oldfmt && !has_id) return 0;
	has_ext = de_input_file_has_ext(c, "pif");
	if(maybe_oldfmt) {
		return has_ext ? 24 : 0;
	}
	return has_ext ? 100 : 35;
}

static void de_help_pif(deark *c)
{
	de_msg(c, "-opt oemenc=... : The encoding for OEM Text items");
}

void de_module_pif(deark *c, struct deark_module_info *mi)
{
	mi->id = "pif";
	mi->desc = "Windows Program Information File";
	mi->identify_fn = de_identify_pif;
	mi->run_fn = de_run_pif;
	mi->help_fn = de_help_pif;
}

static void de_run_desqview_dvp(deark *c, de_module_params *mparams)
{
	do_pif_main(c, mparams, 1);
}

static int de_identify_desqview_dvp(deark *c)
{
	int has_ext;

	if(c->infile->len!=416) return 0;
	if(de_getbyte(0) != 0x00) return 0;
	has_ext = de_input_file_has_ext(c, "dvp");
	if(has_ext) return 40;
	return 0;
}

void de_module_desqview_dvp(deark *c, struct deark_module_info *mi)
{
	mi->id = "desqview_dvp";
	mi->desc = "DESQview Program Information File";
	mi->identify_fn = de_identify_desqview_dvp;
	mi->run_fn = de_run_desqview_dvp;
}
