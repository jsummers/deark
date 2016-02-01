// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// STOS Memory Bank (MBK)

#include <deark-config.h>
#include <deark-modules.h>
#include "fmtutil.h"

typedef struct localctx_struct {
	de_int64 banknum;
	de_byte banktype;
	de_int64 banksize;
	de_uint32 data_bank_id;
	de_uint32 pal[256];
} lctx;

static const char* sprite_res_name[3] = { "low", "med", "high" };
static const de_byte sprite_res_bpp[3] = { 4, 2, 1 };

// Decode one sprite
static void do_sprite_param_block(deark *c, lctx *d, de_int64 res,
	de_int64 sprite_index, de_int64 param_blk_pos, de_int64 pos)
{
	de_int64 sprite_data_offs_raw;
	de_int64 width_raw; // = width_in_pixels/16
	de_int64 mask_offs;
	de_int64 mask_size;
	de_int64 fg_offs;
	de_int64 fg_size;
	struct atari_img_decode_data *adata_fg = NULL;
	struct atari_img_decode_data *adata_mask = NULL;
	de_uint32 mask_pal[2] = { DE_STOCKCOLOR_WHITE, DE_STOCKCOLOR_BLACK };

	de_dbg(c, "%s-res sprite #%d param block at %d\n", sprite_res_name[res],
		(int)sprite_index, (int)pos);
	de_dbg_indent(c, 1);
	adata_fg = de_malloc(c, sizeof(struct atari_img_decode_data));
	adata_mask = de_malloc(c, sizeof(struct atari_img_decode_data));

	adata_fg->bpp = (de_int64)sprite_res_bpp[res];
	adata_fg->ncolors = ((de_int64)1)<<adata_fg->bpp;
	adata_mask->bpp = 1;
	adata_mask->ncolors = 2;

	sprite_data_offs_raw = de_getui32be(pos);

	//de_dbg(c, "sprite data offset: %d (->%d)\n", (int)sprite_data_offs_raw, (int)mask_offs);
	width_raw = (de_int64)de_getbyte(pos+4);
	adata_fg->w = width_raw*16;
	adata_fg->h = (de_int64)de_getbyte(pos+5);
	de_dbg(c, "dimensions: %dx%d\n", (int)adata_fg->w, (int)adata_fg->h);
	if(!de_good_image_dimensions(c, adata_fg->w, adata_fg->h)) goto done;

	adata_mask->w = adata_fg->w;
	adata_mask->h = adata_fg->h;
	mask_offs = param_blk_pos + sprite_data_offs_raw;
	mask_size = (width_raw * 2 * 1) * adata_mask->h;
	de_dbg(c, "mask image at %d, len=%d\n", (int)mask_offs, (int)mask_size);
	if(mask_offs>=c->infile->len) goto done;

	fg_offs = mask_offs + mask_size;
	fg_size = (width_raw * 2 * adata_fg->bpp) * adata_fg->h;
	de_dbg(c, "foreground image at %d, len=%d\n", (int)fg_offs, (int)fg_size);

	adata_mask->unc_pixels = dbuf_open_input_subfile(c->infile, mask_offs, mask_size);
	adata_fg->unc_pixels = dbuf_open_input_subfile(c->infile, fg_offs, fg_size);

	adata_mask->pal = mask_pal;
	adata_fg->pal = d->pal;

	adata_mask->img = de_bitmap_create(c, adata_fg->w, adata_fg->h, 1);
	adata_fg->img = de_bitmap_create(c, adata_fg->w, adata_fg->h, 4);

	de_fmtutil_atari_decode_image(c, adata_mask);
	de_fmtutil_atari_decode_image(c, adata_fg);
	de_bitmap_apply_mask(adata_fg->img, adata_mask->img, 0);
	de_fmtutil_atari_set_standard_density(c, adata_fg);
	de_bitmap_write_to_file(adata_fg->img, NULL);

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
	de_dbg_indent(c, -1);
}

// A block of sprites for a particular resolution
static void do_sprite_param_blocks(deark *c, lctx *d, de_int64 res,
	de_int64 nsprites, de_int64 pos)
{
	de_int64 k;
	de_dbg(c, "%s-res sprite param blocks at %d\n", sprite_res_name[res],
		(int)pos);

	de_dbg_indent(c, 1);
	for(k=0; k<nsprites; k++) {
		do_sprite_param_block(c, d, res, k, pos, pos + 8*k);
	}
	de_dbg_indent(c, -1);
}

static void read_sprite_palette(deark *c, lctx *d, de_int64 pos)
{
	de_int64 n;

	if(pos>=c->infile->len) return;

	n = de_getui32be(pos);
	if(n!=0x50414c54) {
		de_warn(c, "Sprite palette not found (expected at %d)\n", (int)pos);
		return;
	}
	de_dbg(c, "sprite palette at %d\n", (int)pos);
	de_dbg_indent(c, 1);
	de_fmtutil_read_atari_palette(c, c->infile, pos+4, d->pal, 16, 16);
	de_dbg_indent(c, -1);
}

static void do_sprite_bank(deark *c, lctx *d, de_int64 pos)
{
	de_int64 res;
	de_int64 paramoffs_raw[3]; // One for each resolution: low, med, hi
	de_int64 paramoffs[3];
	de_int64 nsprites[3];
	de_int64 nsprites_total = 0;
	de_int64 pal_pos;

	de_dbg(c, "sprite bank\n");
	for(res=0; res<3; res++) {
		paramoffs_raw[res] = de_getui32be(pos+4+4*res);
		// paramoffs is relative to the first position after the ID.
		paramoffs[res] = pos + 4 + paramoffs_raw[res];
		nsprites[res] = de_getui16be(pos+16+2*res);
		de_dbg(c, "%s-res sprites: %d, param blk offset: %d (-> %d)\n", sprite_res_name[res],
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

static void do_mbk_data_bank(deark *c, lctx *d, de_int64 pos)
{
	de_dbg(c, "STOS data bank at %d\n", (int)pos);
	de_dbg_indent(c, 1);
	d->data_bank_id = (de_uint32)de_getui32be(pos);
	de_dbg(c, "data bank id: 0x%08x\n", (unsigned int)d->data_bank_id);

	switch(d->data_bank_id) {
	case 0x19861987U:
		do_sprite_bank(c, d, pos);
		break;
	}
	de_dbg_indent(c, -1);
}

static void do_mbk(deark *c, lctx *d)
{
	de_int64 pos = 0;

	de_dbg(c, "MBK header at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	de_dbg(c, "bank number: %d\n", (int)d->banknum);

	d->banksize = de_getui32be(14);
	d->banktype = (de_byte)(d->banksize>>24);
	d->banksize &= (de_int64)0x00ffffff;
	de_dbg(c, "bank type: 0x%02x\n", (unsigned int)d->banktype);
	de_dbg(c, "bank size: %d\n", (int)d->banksize);

	de_dbg_indent(c, -1);

	pos += 18;

	if(d->banktype==0x81) {
		do_mbk_data_bank(c, d, pos);
	}
}

static void do_mbs(deark *c, lctx *d)
{
	de_int64 pos = 0;
	de_dbg(c, "MBS header at %d\n", (int)pos);
}

static void de_run_mbk_mbs(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->banknum = de_getui32be(10);
	if(d->banknum==0) {
		de_declare_fmt(c, "STOS MBS");
		do_mbs(c, d);
	}
	else {
		de_declare_fmt(c, "STOS MBK");
		do_mbk(c, d);
	}

	de_free(c, d);
}

static int de_identify_mbk(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "Lionpoubnk", 10))
		return 100;
	return 0;
}

void de_module_mbk(deark *c, struct deark_module_info *mi)
{
	mi->id = "mbk";
	mi->desc = "STOS Memory Bank";
	mi->run_fn = de_run_mbk_mbs;
	mi->identify_fn = de_identify_mbk;
}
