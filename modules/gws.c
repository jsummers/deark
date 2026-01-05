// This file is part of Deark.
// Copyright (C) 2024 Jason Summers
// See the file COPYING for terms of use.

// Graphic Workshop, and other formats by Alchemy Mindworks.
// [Note: Alchemy Mindworks and Image Alchemy are not related, AFAIK.]

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_imggal_alch);
DE_DECLARE_MODULE(de_module_gws_thn);
DE_DECLARE_MODULE(de_module_gws_exepic);

// **************************************************************************
// Image Gallery gallery file (Alchemy Mindworks)
// **************************************************************************

static void datetime_dbgmsg(deark *c, struct de_timestamp *ts, const char *name)
{
	char timestamp_buf[64];

	de_timestamp_to_string(ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "%s: %s", name, timestamp_buf);
}

#define IMGGAL_HDRSIZE 97

struct imggal_member {
	i64 npwidth, pdwidth, height;
	i64 bytes_per_row_per_plane;
	i64 rowspan;
	de_ucstring *orig_name;
	de_ucstring *name;
	struct de_timestamp create_dt;
	struct de_timestamp mod_dt;
	de_color pal[256];
};

struct imggal_ctx {
	de_encoding input_encoding;
	u8 imgtype;
	u8 need_errmsg;
	u8 is_color;
	i64 item_count;
	i64 item_size;
	i64 bpp;
};

// Assumes path separators are  '/' or '\'.
// FIXME: This may be duplicated in misc2.c.
static void get_base_filename(de_ucstring *s1, de_ucstring *s2)
{
	i64 i;
	i64 len;

	ucstring_empty(s2);
	len = s1->len;
	for(i=0; i<len; i++) {
		de_rune ch;

		ch = s1->str[i];
		if(ch=='\\' || ch=='/') {
			ucstring_empty(s2);
		}
		else {
			ucstring_append_char(s2, ch);
		}
	}
}

// Returns 0 on fatal error
static int do_imggal_member(deark *c, struct imggal_ctx *d, i64 idx, i64 pos1)
{
	int saved_indent_level;
	int retval = 1; // Default to no-fatal-error
	i64 pos = pos1;
	struct imggal_member *md = NULL;
	de_bitmap *img = NULL;
	de_finfo *fi = NULL;
	i64 t;
	static const de_color alchpal[16] = {
		0xff000000U,0xffff0000U,0xff00ff00U,0xffffff00U,
		0xff0000ffU,0xffff00ffU,0xff00ffffU,0xffd3a292U,
		0xffa26159U,0xff929292U,0xff7d0000U,0xff007d00U,
		0xff00007dU,0xffd3d3d3U,0xff515151U,0xffffffffU };

	de_dbg_indent_save(c, &saved_indent_level);
	md = de_malloc(c, sizeof(struct imggal_member));
	de_dbg(c, "item at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);

	t = de_geti32le_p(&pos);
	de_unix_time_to_timestamp(t, &md->create_dt, 0x1);
	datetime_dbgmsg(c, &md->create_dt, "create time");
	t = de_geti32le_p(&pos);
	de_unix_time_to_timestamp(t, &md->mod_dt, 0x1);
	datetime_dbgmsg(c, &md->mod_dt, "mod time");

	pos += 28; // various fields

	md->orig_name = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 80, md->orig_name, DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
	de_dbg(c, "orig name: \"%s\"", ucstring_getpsz_d(md->orig_name));
	pos += 81;
	md->name = ucstring_create(c);
	get_base_filename(md->orig_name, md->name);

	pos += 14; // ?
	pos += 257; // description
	pos += 257; // keywords

	md->npwidth = 1 + de_getu16le_p(&pos);
	md->height = 1 + de_getu16le_p(&pos);
	de_dbg_dimensions(c, md->npwidth, md->height);
	if(!de_good_image_dimensions(c, md->npwidth, md->height)) goto done;

	md->bytes_per_row_per_plane = (md->npwidth + 7)/8;
	md->rowspan = md->bytes_per_row_per_plane * d->bpp;
	md->pdwidth = md->bytes_per_row_per_plane * 8;

	if(pos+(md->rowspan*md->height) > pos1+d->item_size) {
		retval = 0;
		d->need_errmsg = 1;
		goto done;
	}

	img = de_bitmap_create2(c, md->npwidth, md->pdwidth, md->height, (d->is_color?3:1));
	fi = de_finfo_create(c);

	if(d->is_color) {
		de_memcpy(md->pal, alchpal, sizeof(alchpal));
	}
	else if(d->bpp==1) {
		md->pal[0] = DE_STOCKCOLOR_BLACK;
		md->pal[1] = DE_MAKE_GRAY(243);
	}
	else {
		UI k;

		// Note: The Image Gallery software, in grayscale mode, uses a palette
		// that doesn't go all the way to white. The whitest color is 243 when
		// emulated by DOSBox.
		// We'll respect that, though whether we should do so is debatable.
		for(k=0; k<16; k++) {
			md->pal[k] = DE_MAKE_GRAY((u8)((k * 65) / 4));
		}
	}
	de_convert_image_paletted_planar(c->infile, pos, d->bpp,
		md->bytes_per_row_per_plane * d->bpp, md->bytes_per_row_per_plane,
		md->pal, img, 0);

	if(c->filenames_from_file) {
		de_finfo_set_name_from_ucstring(c, fi, md->name, 0);
	}
	fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = md->mod_dt;
	fi->timestamp[DE_TIMESTAMPIDX_CREATE] = md->create_dt;
	de_bitmap_write_to_file_finfo(img, fi, DE_CREATEFLAG_OPT_IMAGE);

done:
	de_dbg_indent_restore(c, saved_indent_level);
	de_finfo_destroy(c, fi);
	de_bitmap_destroy(img);
	if(md) {
		ucstring_destroy(md->orig_name);
		ucstring_destroy(md->name);
		de_free(c, md);
	}
	return retval;
}

static void de_run_imggal_alch(deark *c, de_module_params *mparams)
{
	struct imggal_ctx *d = NULL;
	const char *s;
	i64 i;

	d = de_malloc(c, sizeof(struct imggal_ctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP437);

	// 8: gallery comment

	d->item_count = de_getu16le(73);
	de_dbg(c, "number of items: %d", (int)d->item_count);

	d->imgtype = de_getbyte(75);
	de_dbg(c, "image type: %u", (UI)d->imgtype);
	de_dbg_indent(c, 1);

	s = (d->imgtype<=1 || d->imgtype==4) ? "portrait" : "landscape";
	de_dbg(c, "orientation: %s", s);

	if(d->imgtype==1 || d->imgtype==3) {
		s = "grayscale";
		d->bpp = 4;
	}
	else if(d->imgtype==4 || d->imgtype==5) {
		s = "color";
		d->is_color = 1;
		d->bpp = 4;
	}
	else {
		s = "bilevel";
		d->bpp = 1;
	}
	de_dbg(c, "color mode: %s", s);

	de_dbg_indent(c, -1);

	d->item_size = de_getu16le(87);
	de_dbg(c, "item size: %"I64_FMT, d->item_size);

	// 89: gallery creation time
	// 93: gallery last-modified time

	if(d->imgtype>5) {
		d->need_errmsg = 1;
		goto done;
	}

	if(d->item_size<649 || (IMGGAL_HDRSIZE+d->item_count*d->item_size > c->infile->len)) {
		d->need_errmsg = 1;
		goto done;
	}

	for(i=0; i<d->item_count; i++) {
		if(!do_imggal_member(c, d, i, IMGGAL_HDRSIZE+i*d->item_size)) {
			goto done;
		}
	}

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Invalid or unsupported GAL file");
		}
		de_free(c, d);
	}
}

static int de_identify_imggal_alch(deark *c)
{
	u8 b;

	if(c->infile->len<IMGGAL_HDRSIZE) return 0;
	if(dbuf_memcmp(c->infile, 0, "ALCHGLRY", 8)) return 0;
	b = de_getbyte(75);
	if(b>0x05) return 0;
	return 100;
}

void de_module_imggal_alch(deark *c, struct deark_module_info *mi)
{
	mi->id = "imggal_alch";
	mi->desc = "Image Gallery GAL (Alchemy Mindworks)";
	mi->run_fn = de_run_imggal_alch;
	mi->identify_fn = de_identify_imggal_alch;
}

// **************************************************************************
// Graphic Workshop .THN
// **************************************************************************

struct gws_thn_ctx {
	de_encoding input_encoding;
	de_color pal[256];
};

static void gwsthn_makepal_orig(deark *c, struct gws_thn_ctx *d)
{
	// Original palette
	// Based on Graphic Workshop v1.1a for Windows
	static const u8 rbvals[6] = {0x00,0x57,0x83,0xab,0xd7,0xff};
	static const u8 gvals[7] = {0x00,0x2b,0x57,0x83,0xab,0xd7,0xff};
	static const de_color gwspal_last5[5] = {
		0xff3f3f3fU,0xff6b6b6bU,0xff979797U,0xffc3c3c3U,0xffffffffU
	};
	UI k;

	for(k=0; k<=250; k++) {
		d->pal[k] = DE_MAKE_RGB(
			rbvals[k%6],
			gvals[(k%42)/6],
			rbvals[k/42]);
	}
	for(k=251; k<=255; k++) {
		d->pal[k] = gwspal_last5[k-251];
	}
}

static void gwsthn_makepal_new(deark *c, struct gws_thn_ctx *d)
{
	// New palette (really RGB332), introduced by v1.1c
	// Based on Graphic Workshop v1.1u for Windows
	UI k;

	for(k=0; k<256; k++) {
		u8 r, g, b;
		r = de_sample_nbit_to_8bit(3, k>>5);
		g = de_sample_nbit_to_8bit(3, (k>>2)&0x07);
		b = de_sample_nbit_to_8bit(2, k&0x03);
		d->pal[k] = DE_MAKE_RGB(r, g, b);
	}
}

static void de_run_gws_thn(deark *c, de_module_params *mparams)
{
	struct gws_thn_ctx *d = NULL;
	de_bitmap *img = NULL;
	u8 v1, v2;
	i64 w, h;
	i64 pos;
	de_ucstring *s = NULL;

	d = de_malloc(c, sizeof(struct gws_thn_ctx));

	// This code is based on reverse engineering, and may be incorrect.
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);
	pos = 4;
	v1 = de_getbyte_p(&pos);
	v2 = de_getbyte_p(&pos);
	de_dbg(c, "version?: 0x%02x 0x%02x", (UI)v1, (UI)v2);

	s = ucstring_create(c);
	// For the text fields, the field size appears to be 129, but the software
	// only properly supports up to 127 non-NUL bytes.
	dbuf_read_to_ucstring(c->infile, 6, 127, s, DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
	if(s->len>0) de_dbg(c, "comments: \"%s\"", ucstring_getpsz_d(s));
	ucstring_empty(s);
	dbuf_read_to_ucstring(c->infile, 135, 127, s, DE_CONVFLAG_STOP_AT_NUL, d->input_encoding);
	if(s->len>0) de_dbg(c, "key words: \"%s\"", ucstring_getpsz_d(s));

	pos = 264;
	de_dbg(c, "image at %"I64_FMT, pos);
	w = 96;
	h = 96;

	// Set up the palette. There are two possible fixed palettes.
	if(v1==0) {
		gwsthn_makepal_orig(c, d);
	}
	else {
		gwsthn_makepal_new(c, d);
	}

	img = de_bitmap_create(c, w, h, 3);
	de_convert_image_paletted(c->infile, pos, 8, w, d->pal, img, 0);
	de_bitmap_write_to_file(img, NULL, DE_CREATEFLAG_FLIP_IMAGE);

	de_bitmap_destroy(img);
	ucstring_destroy(s);
	de_free(c, d);
}

static int de_identify_gws_thn(deark *c)
{
	if(c->infile->len!=9480) return 0;
	if(!dbuf_memcmp(c->infile, 0, "THNL", 4)) return 100;
	return 0;
}

void de_module_gws_thn(deark *c, struct deark_module_info *mi)
{
	mi->id = "gws_thn";
	mi->desc = "Graphic Workshop thumbnail .THN";
	mi->run_fn = de_run_gws_thn;
	mi->identify_fn = de_identify_gws_thn;
}

// **************************************************************************
// GWS self-displaying picture (DOS EXE format)
// **************************************************************************

struct gws_exepic_ctx {
	u8 need_errmsg;
	UI cmpr_meth;
	i64 imgpos;
	i64 depth_raw;
	i64 depth_adj;
	i64 w, h;
	i64 nplanes;
	i64 unc_image_size;
	i64 byprpp; // bytes per row per plane
	i64 ncolors;
	const char *msgpfx;
	struct fmtutil_exe_info *ei;
	struct fmtutil_specialexe_detection_data edd;
	de_color pal[256];
};

static void gwsexe_decompress(deark *c, struct gws_exepic_ctx *d, dbuf *unc_pixels)
{
	i64 ipos = d->imgpos;
	i64 nbytes_decompressed = 0;

	while(1) {
		u8 b0;
		u8 val;
		i64 count;

		if(ipos >= c->infile->len) goto done;
		if(nbytes_decompressed >= d->unc_image_size) goto done;

		b0 = de_getbyte_p(&ipos);
		if(b0 < 0xc0) {
			count = 1;
			val = b0;
		}
		else {
			// TODO: Figure out what opcode 0xc0 means. I've never seen it used.
			count = (i64)(b0-0xc0);
			val = de_getbyte_p(&ipos);
		}

		dbuf_write_run(unc_pixels, val, count);
		nbytes_decompressed += count;
	}
done:
	dbuf_flush(unc_pixels);
}

static void gwsexe_decode_decompressed_image(deark *c, struct gws_exepic_ctx *d,
	dbuf *inf, i64 inf_pos)
{
	de_bitmap *img = NULL;

	img = de_bitmap_create(c, d->w, d->h, 3);
	if(d->nplanes>1) {
		de_convert_image_paletted_planar(inf, inf_pos, d->nplanes,
			d->byprpp*d->nplanes, d->byprpp, d->pal, img, 0x2);
	}
	else {
		de_convert_image_paletted(inf, inf_pos, d->depth_adj, d->byprpp, d->pal,
			img, 0);
	}
	de_bitmap_write_to_file(img, NULL, 0);
	de_bitmap_destroy(img);
}

static void do_gwsexe_image(deark *c, struct gws_exepic_ctx *d)
{
	dbuf *unc_pixels = NULL;

	de_dbg(c, "image at %"I64_FMT, d->imgpos);
	de_dbg_indent(c, 1);
	if(d->cmpr_meth==2) {
		unc_pixels = dbuf_create_membuf(c, d->unc_image_size, 0x1);
		dbuf_enable_wbuffer(unc_pixels);
		gwsexe_decompress(c, d, unc_pixels);
		gwsexe_decode_decompressed_image(c, d, unc_pixels, 0);
	}
	else {
		gwsexe_decode_decompressed_image(c, d, c->infile, d->imgpos);
	}

	dbuf_close(unc_pixels);
	de_dbg_indent(c, -1);
}

static void de_run_gws_exepic(deark *c, de_module_params *mparams)
{
	struct gws_exepic_ctx *d = NULL;
	i64 pos;

	d = de_malloc(c, sizeof(struct gws_exepic_ctx));
	d->msgpfx = "[GWS picture] ";
	d->ei = de_malloc(c, sizeof(struct fmtutil_exe_info));

	fmtutil_collect_exe_info(c, c->infile, d->ei);

	d->edd.restrict_to_fmt = DE_SPECIALEXEFMT_GWS_EXEPIC;
	fmtutil_detect_specialexe(c, d->ei, &d->edd);
	if(d->edd.detected_fmt!=DE_SPECIALEXEFMT_GWS_EXEPIC) {
		d->need_errmsg = 1;
		goto done;
	}

	pos = d->ei->start_of_dos_code + 9;

	// My best guess as to how to calculate the image position.
	// The field at CS:9 is not actually used by the executable code. Instead
	// it's overwritten with a hardcoded value that is observed to be identical.
	// Then it is adjusted in some way.
	d->imgpos = de_getu16le_p(&pos);
	d->imgpos = de_pad_to_n(d->imgpos, 16);
	d->imgpos = d->ei->start_of_dos_code + d->imgpos;
	de_dbg(c, "img pos: %"I64_FMT, d->imgpos);

	d->w = de_getu16le_p(&pos);
	d->h = de_getu16le_p(&pos);
	de_dbg_dimensions(c, d->w, d->h);
	d->byprpp = de_getu16le_p(&pos);
	de_dbg(c, "bytes/row/plane: %u", (UI)d->byprpp);
	d->depth_raw = de_getu16le_p(&pos);
	de_dbg(c, "depth: %u", (UI)d->depth_raw);
	d->cmpr_meth = (UI)de_getu16le_p(&pos);
	de_dbg(c, "cmpr meth: %u", d->cmpr_meth);
	if(d->depth_raw<1 || d->depth_raw>8) {
		d->need_errmsg = 1;
		goto done;
	}
	if(d->depth_raw>=5) {
		d->depth_adj = 8;
		d->nplanes = 1;
	}
	else {
		d->depth_adj = d->depth_raw;
		d->nplanes = d->depth_raw;
	}

	d->unc_image_size = d->byprpp * d->nplanes * d->h;
	d->ncolors = (i64)1 << d->depth_raw;
	de_read_simple_palette(c, c->infile, d->ei->start_of_dos_code+54,
		d->ncolors, 3, d->pal, 256, DE_RDPALTYPE_24BIT, 0);

	if(d->cmpr_meth!=1 && d->cmpr_meth!=2) {
		de_err(c, "%sUnsupported compression", d->msgpfx);
		goto done;
	}

	if(!de_good_image_dimensions(c, d->w, d->h)) {
		goto done;
	}

	do_gwsexe_image(c, d);

done:
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "%sBad or unsupported GWS EXE picture", d->msgpfx);
		}
		de_free(c, d->ei);
		de_free(c, d);
	}
}

void de_module_gws_exepic(deark *c, struct deark_module_info *mi)
{
	mi->id = "gws_exepic";
	mi->desc = "Graphic Workshop self-displaying picture";
	mi->run_fn = de_run_gws_exepic;
}
