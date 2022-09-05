// This file is part of Deark.
// Copyright (C) 2021 Jason Summers
// See the file COPYING for terms of use.

// Windows CLP saved clipboard format

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_clp);

// TODO: Support ENHMETAFILE, TIFF, RIFF, WAVE
#define CFMT_TEXT          1
#define CFMT_BITMAP        2
#define CFMT_METAFILEPICT  3
//#define CFMT_SYLK          4
//#define CFMT_DIF           5
//#define CFMT_TIFF          6
#define CFMT_OEMTEXT       7
#define CFMT_DIB           8
#define CFMT_PALETTE       9
//#define CFMT_PENDATA       10
//#define CFMT_RIFF          11
//#define CFMT_WAVE          12
#define CFMT_UNICODETEXT   13
//#define CFMT_ENHMETAFILE   14
//#define CFMT_HDROP         15
#define CFMT_LOCALE        16
#define CFMT_DIBV5         17
//#define CFMT_OWNERDISPLAY     0x80
#define CFMT_DSPTEXT          0x81
#define CFMT_DSPBITMAP        0x82
#define CFMT_DSPMETAFILEPICT  0x83
//#define CFMT_DSPENHMETAFILE   0x8e

struct index_item {
	u8 handled;
	UI clpfmt;
	i64 dpos;
	i64 dlen;
};

struct member_data {
	UI idx;
	i64 hpos;
	de_finfo *fi;
	de_ucstring *name;
	u8 clpfmtname_known;
	char clpfmtname_sz[32];
};

typedef struct localctx_struct {
	UI sig;
	u8 extractall;
	u8 ddb_warned;
	de_encoding input_encoding_ansi;
	de_encoding input_encoding_oem;
	i64 num_items;
	i64 index_pos;
	i64 index_item_len;
	i64 next_avail_dpos;
	struct index_item *index_array; // array[num_items]
	u8 have_pal;
	de_color pal[256];
} lctx;

static void destroy_md(deark *c, struct member_data *md)
{
	if(!md) return;
	de_finfo_destroy(c, md->fi);
	ucstring_destroy(md->name);
	de_free(c, md);
}

static int get_cf_name(deark *c, lctx *d, UI clpfmt, char *buf, size_t buflen)
{
	static const char *names[18] = { NULL, "TEXT", "BITMAP", "METAFILEPICT",
		"SYLK", "DIF", "TIFF", "OEMTEXT", "DIB", "PALETTE", "PENDATA", "RIFF",
		"WAVE", "UNICODETEXT", "ENHMETAFILE", "HDROP", "LOCALE", "DIBV5" };

	if((size_t)clpfmt<DE_ARRAYCOUNT(names) && names[clpfmt]) {
		de_snprintf(buf, buflen, "CF_%s", names[clpfmt]);
		return 1;
	}
	// TODO: CF_OWNERDISPLAY, etc.
	de_strlcpy(buf, "?", buflen);
	return 0;
}

static void extract_binary(deark *c, lctx *d, struct member_data *md, struct index_item *ii)
{
	if(ii->dlen<=0) goto done;
	dbuf_create_file_from_slice(c->infile, ii->dpos, ii->dlen, "bin", md->fi, 0);
done:
	;
}

static void create_text_file_from_slice(dbuf *inf, i64 pos1, i64 len,
	de_ext_encoding ee, const char *ext, de_finfo *fi)
{
	dbuf *outf = NULL;

	outf = dbuf_create_output_file(inf->c, ext, fi, 0);
	if(inf->c->write_bom) {
		dbuf_write_uchar_as_utf8(outf, 0xfeff);
	}
	dbuf_copy_slice_convert_to_utf8(inf, pos1, len, ee, outf, 0);
	dbuf_close(outf);
}

static void extract_text(deark *c, lctx *d, struct member_data *md, struct index_item *ii)
{
	de_ext_encoding ee;
	const char *ext;
	i64 dlen = ii->dlen;

	ext = "txt";
	if(ii->clpfmt==CFMT_TEXT || ii->clpfmt==CFMT_DSPTEXT) {
		ee = DE_EXTENC_MAKE(d->input_encoding_ansi, DE_ENCSUBTYPE_HYBRID);
	}
	else if(ii->clpfmt==CFMT_OEMTEXT) {
		ee = DE_EXTENC_MAKE(d->input_encoding_oem, DE_ENCSUBTYPE_HYBRID);
	}
	else if(ii->clpfmt==CFMT_UNICODETEXT) {
		ee = DE_ENCODING_UTF16LE;
	}
	else {
		goto done;
	}

	// Search for the NUL terminator, to refine the data len.
	if(ii->clpfmt==CFMT_UNICODETEXT) {
		i64 bytes_consumed = 0;

		if(dbuf_get_utf16_NULterm_len(c->infile, ii->dpos, ii->dlen, &bytes_consumed)) {
			dlen = bytes_consumed - 2;
		}
	}
	else {
		i64 foundpos = 0;

		if(dbuf_search_byte(c->infile, 0x00, ii->dpos, ii->dlen, &foundpos)) {
			dlen = foundpos - ii->dpos;
		}
	}

	create_text_file_from_slice(c->infile, ii->dpos, dlen, ee, ext, md->fi);
done:
	;
}

static void extract_ddb(deark *c, lctx *d, struct member_data *md, struct index_item *ii)
{
	int old_extract_count;
	de_module_params *mparams = NULL;

	mparams = de_malloc(c, sizeof(de_module_params));
	de_dbg(c, "reading ddb");
	de_dbg_indent(c, 1);
	mparams->in_params.codes = "N";
	mparams->in_params.fi = md->fi;
	if(d->have_pal) {
		mparams->in_params.obj1 = (void*)d->pal;
	}
	old_extract_count = c->num_files_extracted;
	de_run_module_by_id_on_slice(c, "ddb", mparams, c->infile, ii->dpos, ii->dlen);
	de_dbg_indent(c, -1);

	if(c->num_files_extracted>old_extract_count && !d->ddb_warned) {
		de_warn(c, "Nonportable DDB images might not be decoded correctly");
		d->ddb_warned = 1;
	}

	de_free(c, mparams);
}

static void extract_dib(deark *c, lctx *d, struct member_data *md, struct index_item *ii)
{
	de_module_params *mparams = NULL;

	mparams = de_malloc(c, sizeof(de_module_params));
	de_dbg(c, "reading dib");
	de_dbg_indent(c, 1);
	mparams->in_params.fi = md->fi;
	de_run_module_by_id_on_slice(c, "dib", mparams, c->infile, ii->dpos, ii->dlen);
	de_dbg_indent(c, -1);
	de_free(c, mparams);
}

static void extract_wmf(deark *c, lctx *d, struct member_data *md, struct index_item *ii)
{
	if(ii->dlen <= 8) goto done;
	dbuf_create_file_from_slice(c->infile, ii->dpos+8, ii->dlen-8, "wmf", md->fi, 0);
done:
	;
}

static void read_palette(deark *c, lctx *d, struct member_data *md, struct index_item *ii)
{
	i64 dpos, dlen;

	if(d->have_pal) goto done;
	dpos = ii->dpos + 4;
	dlen = ii->dlen - 4;

	de_dbg(c, "reading palette");
	d->have_pal = 1;
	de_dbg_indent(c, 1);
	de_read_palette_rgb(c->infile, dpos, dlen/4, 4,
		d->pal, 256, 0);
	de_dbg_indent(c, -1);

done:
	;
}

// Assign a name to md->fi, if possible
static void set_output_filename(deark *c, lctx *d, struct member_data *md, struct index_item *ii)
{
	i64 i;
	int escape_flag = 0;
	de_ucstring *s = NULL;

	s = ucstring_create(c);

	if(c->filenames_from_file) {
		for(i=0; i<md->name->len; i++) {
			if(md->name->str[i]=='&' && !escape_flag) {
				escape_flag = 1;
			}
			else {
				ucstring_append_char(s, md->name->str[i]);
				escape_flag = 0;
			}
		}
	}

	if(ii->clpfmt==CFMT_BITMAP || ii->clpfmt==CFMT_DSPBITMAP) {
		// Add an indication that this was a device-dependent bitmap
		if(ucstring_isnonempty(s)) {
			ucstring_append_char(s, '.');
		}
		ucstring_append_sz(s, "ddb", DE_ENCODING_LATIN1);
	}

	if(ucstring_isempty(s) && md->clpfmtname_known) {
		ucstring_append_sz(s, md->clpfmtname_sz, DE_ENCODING_UTF8);
	}

	if(ucstring_isnonempty(s)) {
		de_finfo_set_name_from_ucstring(c, md->fi, s, 0);
	}

	ucstring_destroy(s);
}

static void do_item(deark *c, lctx *d, UI idx)
{
	struct index_item *ii;
	struct member_data *md = NULL;
	i64 pos;
	int old_extract_count;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	md = de_malloc(c, sizeof(struct member_data));
	md->idx = idx;
	md->fi = de_finfo_create(c);
	md->name = ucstring_create(c);
	md->hpos = d->index_pos + (i64)md->idx * d->index_item_len;
	ii = &d->index_array[md->idx];
	pos = md->hpos;

	de_dbg(c, "item #%u, header at %"I64_FMT, md->idx, md->hpos);
	de_dbg_indent(c, 1);
	if(d->sig==0xc350) {
		pos += 2; // clipfmt, already read
	}
	else {
		pos += 4;
	}
	md->clpfmtname_known = get_cf_name(c, d, ii->clpfmt, md->clpfmtname_sz, sizeof(md->clpfmtname_sz));
	de_dbg(c, "format: 0x%04x (%s)", ii->clpfmt, md->clpfmtname_sz);
	if(ii->clpfmt==0) goto done;
	pos += 4; // dlen, already read
	pos += 4; // dpos, already read
	de_dbg(c, "data at %"I64_FMT", len=%"I64_FMT, ii->dpos, ii->dlen);

	if(d->sig==0xc350) {
		dbuf_read_to_ucstring(c->infile, pos, 79, md->name, DE_CONVFLAG_STOP_AT_NUL,
			d->input_encoding_ansi);
	}
	else {
		dbuf_read_to_ucstring(c->infile, pos, 79*2, md->name, 0, DE_ENCODING_UTF16LE);
		ucstring_truncate_at_NUL(md->name);
	}
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(md->name));

	if(ii->dlen<1) {
		goto done;
	}

	set_output_filename(c, d, md, ii);

	// So we can figure out if we successfully extracted anything
	old_extract_count = c->num_files_extracted;

	switch(ii->clpfmt) {
	case CFMT_BITMAP: case CFMT_DSPBITMAP:
		extract_ddb(c, d, md, ii);
		break;
	case CFMT_DIB: case CFMT_DIBV5:
		extract_dib(c, d, md, ii);
		break;
	case CFMT_TEXT: case CFMT_OEMTEXT: case CFMT_UNICODETEXT: case CFMT_DSPTEXT:
		extract_text(c, d, md, ii);
		break;
	case CFMT_PALETTE:
		read_palette(c, d, md, ii);
		break;
	case CFMT_METAFILEPICT: case CFMT_DSPMETAFILEPICT:
		extract_wmf(c, d, md, ii);
		break;
	}

	if(c->num_files_extracted==old_extract_count) {
		if(d->extractall) {
			extract_binary(c, d, md, ii);
		}
		else if(c->debug_level>=2) {
			de_dbg_hexdump(c, c->infile, ii->dpos, ii->dlen, 256, NULL, 0x1);
		}
	}

done:
	destroy_md(c, md);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_process_items(deark *c, lctx *d)
{
	UI i;

	// Items to read first (PALETTE, LOCALE)
	for(i=0; i<(UI)d->num_items; i++) {
		if(d->index_array[i].clpfmt==CFMT_PALETTE || d->index_array[i].clpfmt==CFMT_LOCALE) {
			do_item(c, d, i);
			d->index_array[i].handled = 1;
		}
	}

	// Everything else
	for(i=0; i<(UI)d->num_items; i++) {
		if(d->index_array[i].handled==0) {
			do_item(c, d, i);
		}
	}
}

// Returns 0 if we should stop processing the CLP file
static int do_read_index(deark *c, lctx *d)
{
	int retval = 0;
	i64 i;

	// d->num_items is untrusted, but can be no more than 64K.
	d->index_array = de_mallocarray(c, d->num_items, sizeof(struct index_item));

	de_dbg(c, "[scanning index]");
	for(i=0; i<d->num_items; i++) {
		struct index_item *ii;
		i64 pos;

		ii = &d->index_array[i];
		pos = d->index_pos + i*d->index_item_len;

		if(d->sig==0xc350) {
			ii->clpfmt = (UI)de_getu16le_p(&pos);
		}
		else {
			ii->clpfmt = (UI)de_getu32le_p(&pos);
		}
		ii->dlen = de_getu32le_p(&pos);
		ii->dpos = de_getu32le_p(&pos);

		if(ii->clpfmt==0) ii->dlen = 0;

		if(ii->dlen>0) {
			// Sanity check. I don't know if the data segments have to be in order and
			// non-overlapping, but for now I'm assuming they do.
			if((ii->dpos < d->next_avail_dpos) || (ii->dpos+ii->dlen > c->infile->len)) {
				de_err(c, "item %u: Bad data segment position", (UI)i);
				goto done;
			}
			d->next_avail_dpos = ii->dpos+ii->dlen;
		}
	}
	retval = 1;
done:
	return retval;
}

static void de_run_clp(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	const char *tmps;
	int ret;
	i64 pos = 0;

	d = de_malloc(c, sizeof(lctx));

	d->input_encoding_ansi = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);

	d->input_encoding_oem = DE_ENCODING_CP437; // default
	tmps = de_get_ext_option(c, "clp:oemenc");
	if(!tmps) {
		tmps = de_get_ext_option(c, "oemenc");
	}
	if(tmps) {
		d->input_encoding_oem = de_encoding_name_to_code(tmps);
		if(d->input_encoding_oem == DE_ENCODING_UNKNOWN) {
			d->input_encoding_oem = DE_ENCODING_CP437;
		}
	}

	ret =  de_get_ext_option_bool(c, "clp:extractall", -1);
	if(ret>0 || (c->extract_level>=2 && ret!=0)) {
		d->extractall = 1;
	}

	d->sig = (UI)de_getu16le_p(&pos);
	de_dbg(c, "signature: 0x%04x", d->sig);
	if(d->sig<0xc350 || d->sig>0xc352) {
		de_err(c, "Not a Windows CLP file");
		goto done;
	}

	d->num_items = de_getu16le_p(&pos);
	de_dbg(c, "num items: %u", (UI)d->num_items);

	d->index_pos = pos;
	d->index_item_len = (d->sig==0xc350) ? 89 : 172;

	if(!do_read_index(c, d)) goto done;
	do_process_items(c, d);

done:
	if(d) {
		de_free(c, d->index_array);
		de_free(c, d);
	}
}

static int de_identify_clp(deark *c)
{
	int has_ext;
	UI sig;

	// TODO: Improve this
	sig = (UI)de_getu16le(0);
	if(sig<0xc350 || sig>0xc352) return 0;
	has_ext = de_input_file_has_ext(c, "clp");
	if(has_ext) return 80;
	return 15;
}

static void de_help_clp(deark *c)
{
	de_msg(c, "-opt clp:extractall : Extract all items");
	de_msg(c, "-opt oemenc=... : The encoding for OEM Text items");
}

void de_module_clp(deark *c, struct deark_module_info *mi)
{
	mi->id = "clp";
	mi->desc = "Windows Clipboard";
	mi->run_fn = de_run_clp;
	mi->identify_fn = de_identify_clp;
	mi->help_fn = de_help_clp;
}
