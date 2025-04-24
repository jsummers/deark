// This file is part of Deark.
// Copyright (C) 2025 Jason Summers
// See the file COPYING for terms of use.

// Some DIV Games Studio formats

#include <deark-private.h>
DE_DECLARE_MODULE(de_module_div_map);
DE_DECLARE_MODULE(de_module_div_fpg);

#define DIVFMT_MAP 1
#define DIVFMT_FPG 2
#define DIVFMT_F16 3

struct div_image_ctx {
	i64 imgpos;
	i64 item_len;
	i64 bitmap_pos;
	i64 w, h;
	de_ucstring *descr;
	de_ucstring *fn;
	de_finfo *fi;
};

struct div_ctx {
	de_encoding input_encoding;
	u8 fmt;
	u8 is_archive; // fpg or f16
	u8 need_errmsg;
	de_color pal[256];
};

static u8 identify_div_fmt(deark *c)
{
	u8 buf[7];

	if(de_getbyte(3) != 0x1a) return 0;
	de_read(buf, 0, sizeof(buf));
	if(de_memcmp(&buf[4], (const void*)"\x0d\x0a\0", 3)) return 0;
	if(!de_memcmp(buf, (const void*)"map", 3)) return DIVFMT_MAP;
	if(!de_memcmp(buf, (const void*)"fpg", 3)) return DIVFMT_FPG;
	if(!de_memcmp(buf, (const void*)"f16", 3)) return DIVFMT_F16;
	return 0;
}

static void div_image_destroy(deark *c, struct div_image_ctx *md)
{
	if(!md) return;
	ucstring_destroy(md->descr);
	ucstring_destroy(md->fn);
	de_finfo_destroy(c, md->fi);
	de_free(c, md);
}

static void div_read_pal_p(deark *c, struct div_ctx *d, i64 *ppos)
{
	de_read_simple_palette(c, c->infile, *ppos, 256, 3, d->pal, 256,
		DE_RDPALTYPE_VGA18BIT, 0);
	*ppos += 768;
	*ppos += 16*36; // 16 36-byte "pal_range" items
}

static void div_read_descr_p(deark *c, struct div_ctx *d,
	struct div_image_ctx *md, i64 *ppos)
{
	if(!md->descr) {
		md->descr = ucstring_create(c);
	}
	dbuf_read_to_ucstring(c->infile, *ppos, 32, md->descr, DE_CONVFLAG_STOP_AT_NUL,
		DE_EXTENC_MAKE(d->input_encoding, DE_ENCSUBTYPE_HYBRID));
	de_dbg(c, "description: \"%s\"", ucstring_getpsz_d(md->descr));
	*ppos += 32;
}

static void div_convert_f16(deark *c, struct div_ctx *d, struct div_image_ctx *md,
	de_bitmap *img)
{
	i64 i, j;

	for(j=0; j<md->h; j++) {
		i64 pxpos;

		pxpos = md->bitmap_pos + md->w*2*j;
		for(i=0; i<md->w; i++) {
			UI x;
			de_color clr;

			x = (UI)de_getu16le_p(&pxpos);
			clr = de_rgb565_to_888(x);
			de_bitmap_setpixel_rgb(img, i, j, clr);
		}
	}
}

static void div_do_bitmap(deark *c, struct div_ctx *d, struct div_image_ctx *md)
{
	de_bitmap *img = NULL;

	de_dbg(c, "bitmap at %"I64_FMT, md->bitmap_pos);
	if(!de_good_image_dimensions(c, md->w, md->h)) goto done;
	img = de_bitmap_create(c, md->w, md->h, 3);

	if(d->fmt==DIVFMT_F16) {
		div_convert_f16(c, d, md, img);
	}
	else {
		de_convert_image_paletted(c->infile, md->bitmap_pos, 8,
			md->w, d->pal, img, 0);
	}
	de_bitmap_write_to_file_finfo(img, md->fi, DE_CREATEFLAG_OPT_IMAGE);
done:
	de_bitmap_destroy(img);
}

static void div_read_cpoints_p(deark *c, struct div_ctx *d, i64 *ppos)
{
	i64 n;

	// number of 4-byte "cpoints" items
	if(d->is_archive) {
		n = de_getu32le_p(ppos);
	}
	else {
		n = de_getu16le_p(ppos);
	}
	*ppos += 4*n;
}

// **************************************************************************
// DVI Games Studio .MAP
// **************************************************************************

static void de_run_div_map(deark *c, de_module_params *mparams)
{
	struct div_ctx *d = NULL;
	struct div_image_ctx *md = NULL;
	i64 pos;

	de_declare_fmt(c, "DIV MAP");
	d = de_malloc(c, sizeof(struct div_ctx));
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP850);

	md = de_malloc(c, sizeof(struct div_image_ctx));
	if(de_getbyte(7) != 0) {
		d->need_errmsg = 1;
		goto done;
	}

	pos = 8;
	md->w = de_getu16le_p(&pos);
	md->h = de_getu16le_p(&pos);
	de_dbg_dimensions(c, md->w, md->h);

	pos = 16;

	// TODO: Figure out why the description is often garbage
	//div_read_descr_p(c, d, md, &pos);
	pos += 32;

	div_read_pal_p(c, d, &pos);

	div_read_cpoints_p(c, d, &pos);

	md->bitmap_pos = pos;
	div_do_bitmap(c, d, md);

done:
	div_image_destroy(c, md);
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported MAP file");
		}
		de_free(c, d);
	}
}

static int de_identify_div_map(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, (const void*)"map\x1a\x0d\x0a\0", 7)) {
		return 100;
	}
	return 0;
}

void de_module_div_map(deark *c, struct deark_module_info *mi)
{
	mi->id = "div_map";
	mi->desc = "DIV Games Studio .map";
	mi->run_fn = de_run_div_map;
	mi->identify_fn = de_identify_div_map;
}

// **************************************************************************
// DVI Games Studio .FPG
// **************************************************************************

#define FPG_MIN_ITEM_LEN  64

// Caller creates md and sets md->imgpos.
// On fatal error, sets md->item_len to 0 (or leaves it at 0).
static void div_fpg_image(deark *c, struct div_ctx *d,
	struct div_image_ctx *md)
{
	de_bitmap *img = NULL;
	i64 pos;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "image item at %"I64_FMT, md->imgpos);
	de_dbg_indent(c, 1);

	md->fi = de_finfo_create(c);
	pos = md->imgpos;

	pos += 4; // code

	md->item_len = de_getu32le_p(&pos);
	de_dbg(c, "item len: %"I64_FMT, md->item_len);
	if((md->item_len < FPG_MIN_ITEM_LEN) ||
		(md->imgpos+md->item_len > c->infile->len))
	{
		md->item_len = 0;
		goto done;
	}

	div_read_descr_p(c, d, md, &pos);

	md->fn = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, 12, md->fn, DE_CONVFLAG_STOP_AT_NUL,
		d->input_encoding);
	de_dbg(c, "filename: \"%s\"", ucstring_getpsz_d(md->fn));
	if(c->filenames_from_file && ucstring_isnonempty(md->fn)) {
		de_finfo_set_name_from_ucstring(c, md->fi, md->fn, 0);
	}
	pos += 12;

	md->w = de_getu32le_p(&pos);
	md->h = de_getu32le_p(&pos);
	de_dbg_dimensions(c, md->w, md->h);

	div_read_cpoints_p(c, d, &pos);

	md->bitmap_pos = pos;
	div_do_bitmap(c, d, md);

done:
	de_bitmap_destroy(img);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void de_run_div_fpg(deark *c, de_module_params *mparams)
{
	struct div_ctx *d = NULL;
	struct div_image_ctx *md = NULL;
	i64 pos;

	d = de_malloc(c, sizeof(struct div_ctx));
	d->fmt = identify_div_fmt(c);
	if(d->fmt==DIVFMT_FPG) {
		de_declare_fmt(c, "DIV FPG");
	}
	else if(d->fmt==DIVFMT_F16) {
		de_declare_fmt(c, "DIV F16");
	}
	else {
		d->need_errmsg = 1;
		goto done;
	}
	d->is_archive = 1;
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_CP850);

	if(de_getbyte(7) != 0) {
		d->need_errmsg = 1;
		goto done;
	}

	pos = 8;
	if(d->fmt==DIVFMT_FPG) {
		div_read_pal_p(c, d, &pos);
	}

	de_dbg(c, "item sequence at: %"I64_FMT, pos);

	while(1) {
		if(pos+FPG_MIN_ITEM_LEN > c->infile->len) goto done;

		if(md) {
			div_image_destroy(c, md);
		}

		md = de_malloc(c, sizeof(struct div_image_ctx));
		md->imgpos = pos;
		div_fpg_image(c, d, md);
		if(md->item_len < FPG_MIN_ITEM_LEN) goto done;
		pos += md->item_len;
	}

done:
	div_image_destroy(c, md);
	if(d) {
		if(d->need_errmsg) {
			de_err(c, "Bad or unsupported FPG file");
		}
		de_free(c, d);
	}
}

static int de_identify_div_fpg(deark *c)
{
	u8 x;

	x = identify_div_fmt(c);
	if(x==DIVFMT_FPG || x==DIVFMT_F16) return 100;
	return 0;
}

void de_module_div_fpg(deark *c, struct deark_module_info *mi)
{
	mi->id = "div_fpg";
	mi->desc = "DIV Games Studio .fpg";
	mi->run_fn = de_run_div_fpg;
	mi->identify_fn = de_identify_div_fpg;
}
