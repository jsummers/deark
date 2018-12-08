// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// STOS Memory Bank (MBK)

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_mbk);

typedef struct localctx_struct {
	i64 banknum;
	u8 banktype;
	i64 banksize;
	u32 data_bank_id;
	u32 pal[256];
} lctx;

static const char* sprite_res_name[3] = { "low", "med", "high" };
static const u8 sprite_res_bpp[3] = { 4, 2, 1 };

// Decode one sprite
static void do_sprite_param_block(deark *c, lctx *d, i64 res,
	i64 sprite_index, i64 param_blk_pos, i64 pos)
{
	i64 sprite_data_offs_raw;
	i64 width_raw; // = width_in_pixels/16
	i64 mask_offs;
	i64 mask_size;
	i64 fg_offs;
	i64 fg_size;
	struct atari_img_decode_data *adata_fg = NULL;
	struct atari_img_decode_data *adata_mask = NULL;
	de_finfo *fi = NULL;
	u32 mask_pal[2] = { DE_STOCKCOLOR_WHITE, DE_STOCKCOLOR_BLACK };

	de_dbg(c, "%s-res sprite #%d param block at %d", sprite_res_name[res],
		(int)sprite_index, (int)pos);
	de_dbg_indent(c, 1);
	adata_fg = de_malloc(c, sizeof(struct atari_img_decode_data));
	adata_mask = de_malloc(c, sizeof(struct atari_img_decode_data));

	adata_fg->bpp = (i64)sprite_res_bpp[res];
	adata_fg->ncolors = ((i64)1)<<adata_fg->bpp;
	adata_mask->bpp = 1;
	adata_mask->ncolors = 2;

	sprite_data_offs_raw = de_getu32be(pos);

	//de_dbg(c, "sprite data offset: %d (->%d)", (int)sprite_data_offs_raw, (int)mask_offs);
	width_raw = (i64)de_getbyte(pos+4);
	adata_fg->w = width_raw*16;
	adata_fg->h = (i64)de_getbyte(pos+5);
	de_dbg_dimensions(c, adata_fg->w, adata_fg->h);
	if(!de_good_image_dimensions(c, adata_fg->w, adata_fg->h)) goto done;

	adata_mask->w = adata_fg->w;
	adata_mask->h = adata_fg->h;
	mask_offs = param_blk_pos + sprite_data_offs_raw;
	mask_size = (width_raw * 2 * 1) * adata_mask->h;
	de_dbg(c, "mask image at %d, len=%d", (int)mask_offs, (int)mask_size);
	if(mask_offs>=c->infile->len) goto done;

	fg_offs = mask_offs + mask_size;
	fg_size = (width_raw * 2 * adata_fg->bpp) * adata_fg->h;
	de_dbg(c, "foreground image at %d, len=%d", (int)fg_offs, (int)fg_size);

	adata_mask->unc_pixels = dbuf_open_input_subfile(c->infile, mask_offs, mask_size);
	adata_fg->unc_pixels = dbuf_open_input_subfile(c->infile, fg_offs, fg_size);

	adata_mask->pal = mask_pal;
	adata_fg->pal = d->pal;

	adata_mask->img = de_bitmap_create(c, adata_fg->w, adata_fg->h, 1);
	adata_fg->img = de_bitmap_create(c, adata_fg->w, adata_fg->h, 4);

	de_fmtutil_atari_decode_image(c, adata_mask);
	de_fmtutil_atari_decode_image(c, adata_fg);
	de_bitmap_apply_mask(adata_fg->img, adata_mask->img, 0);
	fi = de_finfo_create(c);
	de_fmtutil_atari_set_standard_density(c, adata_fg, fi);
	de_bitmap_write_to_file_finfo(adata_fg->img, fi, 0);

done:
	if(adata_fg) {
		dbuf_close(adata_fg->unc_pixels);
		de_bitmap_destroy(adata_fg->img);
		de_free(c, adata_fg);
	}
	if(adata_mask) {
		dbuf_close(adata_mask->unc_pixels);
		de_bitmap_destroy(adata_mask->img);
		de_free(c, adata_mask);
	}
	de_finfo_destroy(c, fi);
	de_dbg_indent(c, -1);
}

// A block of sprites for a particular resolution
static void do_sprite_param_blocks(deark *c, lctx *d, i64 res,
	i64 nsprites, i64 pos)
{
	i64 k;
	de_dbg(c, "%s-res sprite param blocks at %d", sprite_res_name[res],
		(int)pos);

	de_dbg_indent(c, 1);
	for(k=0; k<nsprites; k++) {
		do_sprite_param_block(c, d, res, k, pos, pos + 8*k);
	}
	de_dbg_indent(c, -1);
}

static void read_sprite_palette(deark *c, lctx *d, i64 pos)
{
	i64 n;

	if(pos>=c->infile->len) return;

	n = de_getu32be(pos);
	if(n!=0x50414c54) {
		de_warn(c, "Sprite palette not found (expected at %d)", (int)pos);
		d->pal[0] = DE_STOCKCOLOR_WHITE;
		return;
	}
	de_dbg(c, "sprite palette at %d", (int)pos);
	de_dbg_indent(c, 1);
	de_fmtutil_read_atari_palette(c, c->infile, pos+4, d->pal, 16, 16, 0);
	de_dbg_indent(c, -1);
}

static void do_sprite_bank(deark *c, lctx *d, i64 pos)
{
	i64 res;
	i64 paramoffs_raw[3]; // One for each resolution: low, med, hi
	i64 paramoffs[3];
	i64 nsprites[3];
	i64 nsprites_total = 0;
	i64 pal_pos;

	for(res=0; res<3; res++) {
		paramoffs_raw[res] = de_getu32be(pos+4+4*res);
		// paramoffs is relative to the first position after the ID.
		paramoffs[res] = pos + 4 + paramoffs_raw[res];
		nsprites[res] = de_getu16be(pos+16+2*res);
		de_dbg(c, "%s-res sprites: %d, param blk offset: %d ("DE_CHAR_RIGHTARROW" %d)", sprite_res_name[res],
			(int)nsprites[res], (int)paramoffs_raw[res], (int)paramoffs[res]);
		nsprites_total += nsprites[res];
	}

	// TODO: What's the right way to calculate the position of the palette?
	pal_pos = pos + 22 + (nsprites_total)*8;
	read_sprite_palette(c, d, pal_pos);

	for(res=0; res<3; res++) {
		if(nsprites[res]<1) continue;
		if(paramoffs[res]>(c->infile->len-8)) continue;
		do_sprite_param_blocks(c, d, res, nsprites[res], paramoffs[res]);
	}
}

static void do_icon(deark *c, lctx *d, i64 idx, i64 pos)
{
	de_bitmap *img = NULL;
	i64 format_flag;
	i64 bgcol, fgcol;
	i64 i, j;
	i64 w, h;
	i64 rowspan;
	u8 mskbit, fgbit;
	i64 bitsstart;
	u32 clr;

	de_dbg(c, "icon #%d, at %d", (int)idx, (int)pos);
	de_dbg_indent(c, 1);

	format_flag = de_getu16be(pos+4);
	de_dbg(c, "format flag: 0x%04x", (unsigned int)format_flag);
	bgcol = de_getu16be(pos+6);
	fgcol = de_getu16be(pos+8);
	de_dbg(c, "bgcol: 0x%04x, fgcol: 0x%04x", (unsigned int)bgcol, (unsigned int)fgcol);

	// TODO: I don't know how to figure out what colors to use.
	if(fgcol==0 && bgcol!=0) {
		d->pal[0] = DE_STOCKCOLOR_BLACK;
		d->pal[1] = DE_STOCKCOLOR_WHITE;
	}
	else {
		d->pal[0] = DE_STOCKCOLOR_WHITE;
		d->pal[1] = DE_STOCKCOLOR_BLACK;
	}

	w = 16;
	h = 16;
	rowspan = 4;
	img = de_bitmap_create(c, w, h, 2);

	bitsstart = pos + 10;
	for(j=0; j<h; j++) {
		for(i=0; i<w; i++) {
			mskbit = de_get_bits_symbol(c->infile, 1, bitsstart + j*rowspan, i);
			fgbit = de_get_bits_symbol(c->infile, 1, bitsstart + j*rowspan + 2, i);
			clr = d->pal[(unsigned int)fgbit];
			if(!mskbit) {
				clr = DE_SET_ALPHA(clr, 0);
			}
			de_bitmap_setpixel_rgba(img, i, j, clr);
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);
	de_bitmap_destroy(img);
	de_dbg_indent(c, -1);
}

static void do_icon_bank(deark *c, lctx *d, i64 pos)
{
	i64 num_icons;
	i64 k;

	num_icons = de_getu16be(pos+4);
	de_dbg(c, "number of icons: %d", (int)num_icons);
	for(k=0; k<num_icons; k++) {
		do_icon(c, d, k, pos+6+84*k);
	}
}

static void do_mbk_data_bank(deark *c, lctx *d, i64 pos)
{
	const char *bn = "?";

	de_dbg(c, "STOS data bank at %d", (int)pos);
	de_dbg_indent(c, 1);
	d->data_bank_id = (u32)de_getu32be(pos);

	switch(d->data_bank_id) {
	case 0x06071963U: bn = "packed screen"; break;
	case 0x13490157U: bn = "music bank"; break;
	case 0x28091960U: bn = "icon bank"; break;
	case 0x19861987U: bn = "sprite bank"; break;
	case 0x4d414553U: bn = "Maestro!"; break;
	}

	de_dbg(c, "data bank id: 0x%08x (%s)", (unsigned int)d->data_bank_id, bn);

	switch(d->data_bank_id) {
	case 0x19861987U:
		do_sprite_bank(c, d, pos);
		break;
	case 0x28091960U:
		do_icon_bank(c, d, pos);
		break;
	}
	de_dbg_indent(c, -1);
}

static void do_mbk(deark *c, lctx *d)
{
	i64 pos = 0;
	const char *bt = "?";

	de_dbg(c, "MBK header at %d", (int)pos);
	de_dbg_indent(c, 1);

	de_dbg(c, "bank number: %d", (int)d->banknum);

	d->banksize = de_getu32be(14);
	d->banktype = (u8)(d->banksize>>24);
	d->banksize &= (i64)0x00ffffff;

	switch(d->banktype) {
	case 0x01: bt = "work"; break;
	case 0x02: bt = "screen"; break;
	case 0x81: bt = "data"; break;
	case 0x82: bt = "datascreen"; break;
	case 0x84: bt = "set"; break;
	case 0x85: bt = "packed files"; break;
	}

	de_dbg(c, "bank type: 0x%02x (%s)", (unsigned int)d->banktype, bt);
	de_dbg(c, "bank size: %d", (int)d->banksize);

	de_dbg_indent(c, -1);

	pos += 18;

	if(d->banktype==0x81) {
		do_mbk_data_bank(c, d, pos);
	}
}

static void do_mbs(deark *c, lctx *d)
{
	i64 pos = 0;
	de_dbg(c, "MBS header at %d", (int)pos);
}

static void de_run_mbk_mbs(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	u32 id;
	u8 buf[10];

	d = de_malloc(c, sizeof(lctx));

	de_read(buf, 0, sizeof(buf));
	if(!de_memcmp(buf, "Lionpoubnk", 10)) {
		d->banknum = de_getu32be(10);
		if(d->banknum==0) {
			de_declare_fmt(c, "STOS MBS");
			do_mbs(c, d);
		}
		else {
			de_declare_fmt(c, "STOS MBK");
			do_mbk(c, d);
		}
	}
	else {
		id = (u32)de_getu32be_direct(buf);

		if(id==0x19861987U) {
			de_declare_fmt(c, "STOS Sprite Bank");
			do_sprite_bank(c, d, 0);
		}
		else {
			de_err(c, "Not a (supported) STOS/MBK format");
		}
	}

	de_free(c, d);
}

static int de_identify_mbk(deark *c)
{
	u8 buf[10];

	de_read(buf, 0, sizeof(buf));
	if(!de_memcmp(buf, "Lionpoubnk", 10))
		return 100;
	if(!de_memcmp(buf, "\x19\x86\x19\x87", 4)) { // Sprite bank
		return 100;
	}
	return 0;
}

static void de_help_mbk(deark *c)
{
	de_fmtutil_atari_help_palbits(c);
}

void de_module_mbk(deark *c, struct deark_module_info *mi)
{
	mi->id = "stos";
	mi->desc = "STOS Memory Bank (.MBK)";
	mi->run_fn = de_run_mbk_mbs;
	mi->identify_fn = de_identify_mbk;
	mi->help_fn = de_help_mbk;
}
