// This file is part of Deark.
// Copyright (C) 2022 Jason Summers
// See the file COPYING for terms of use.

// PIF (Windows Program Information File)

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_pif);

#define PIF_BASIC_SECTION_SIZE 369
#define PIF_INVALID_HEADING_POS 0xffff

struct pif_ctx {
	de_encoding input_encoding_oem;
	de_encoding input_encoding_ansi;
	de_ucstring *tmpstr;
	i64 next_section_heading_pos;
	struct de_inthashtable *pos_seen;
};

static int pif_validate_pos(deark *c, struct pif_ctx *d, i64 pos)
{
	if(de_inthashtable_add_item(c, d->pos_seen, pos, NULL)) {
		return 1;
	}
	de_err(c, "Bad offset detected");
	return 0;
}

static void do_pif_section_default(deark *c, struct pif_ctx *d, i64 pos1, i64 len)
{
	de_dbg_hexdump(c, c->infile, pos1, len, 256, NULL, 0x1);
}

static void do_pif_section_basic(deark *c, struct pif_ctx *d, i64 pos1, i64 len)
{
	i64 pos = pos1;
	i64 n;

	pos += 2; // unused, checksum

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
	else {
		do_pif_section_default(c, d, dpos, dlen);
	}

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

static void de_run_pif(deark *c, de_module_params *mparams)
{
	const char *tmps;
	struct pif_ctx *d = NULL;

	d = de_malloc(c, sizeof(struct pif_ctx));
	d->tmpstr = ucstring_create(c);

	d->input_encoding_ansi = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);

	d->input_encoding_oem = DE_ENCODING_CP437; // default
	tmps = de_get_ext_option(c, "pif:oemenc");
	if(tmps) {
		d->input_encoding_oem = de_encoding_name_to_code(tmps);
		if(d->input_encoding_oem == DE_ENCODING_UNKNOWN) {
			d->input_encoding_oem = DE_ENCODING_CP437;
		}
	}

	d->pos_seen = de_inthashtable_create(c);

	if(c->infile->len < PIF_BASIC_SECTION_SIZE+22) {
		do_pif_section_basic(c, d, 0, PIF_BASIC_SECTION_SIZE);
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

static int de_identify_pif(deark *c)
{
	int has_ext;

	// TODO: More research on identifying PIF
	if(c->infile->len < PIF_BASIC_SECTION_SIZE) return 0;
	has_ext = de_input_file_has_ext(c, "pif");
	if(!has_ext) return 0;
	if(c->infile->len == PIF_BASIC_SECTION_SIZE) return 24;
	if(c->infile->len < PIF_BASIC_SECTION_SIZE+22) return 0;
	if(!dbuf_memcmp(c->infile, PIF_BASIC_SECTION_SIZE, (const u8*)"MICROSOFT PIFEX\0", 16))
	{
		return 91;
	}
	return 0;
}

void de_module_pif(deark *c, struct deark_module_info *mi)
{
	mi->id = "pif";
	mi->desc = "Windows Program Information File";
	mi->identify_fn = de_identify_pif;
	mi->run_fn = de_run_pif;
}
