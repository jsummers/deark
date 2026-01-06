// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// STOS Memory Bank (MBK)

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_mbk);
DE_DECLARE_MODULE(de_module_stos_pp1);
DE_DECLARE_MODULE(de_module_stos_pp2);
DE_DECLARE_MODULE(de_module_stos_pp3);
DE_DECLARE_MODULE(de_module_stos_daj);

#define BANKID_PKSCREEN 0x06071963U
#define BANKID_SPRITE   0x19861987U

#define PKPIC_IMGTYPE_UNKNOWN 99
#define PKPIC_IMGTYPE_LOW     100
#define PKPIC_IMGTYPE_MED     101
#define PKPIC_IMGTYPE_HIGH    102
#define PKPIC_IMGTYPE_PP1     110
#define PKPIC_IMGTYPE_PP3     112
#define PKPIC_IMGTYPE_M4P     120

static const u8 *g_lion_sig = (const u8*)"Lionpoubnk";

struct pkpic_ctx {
	UI res_code;
	UI imgtype; // PKPIC_IMGTYPE_*
	i64 width_in_words;
	i64 height_in_lumps;
	i64 lines_per_lump;
	i64 pseudowidth, pseudoheight;
	i64 w, h;
	i64 picdata_rel, picdata_abs;
	i64 rledata_rel, rledata_abs;
	i64 pointdata_rel, pointdata_abs;
	i64 unc_image_size;
};

typedef struct localctx_struct {
	u8 is_container_fmt;
	UI imgtype_of_res0; // PKPIC_IMGTYPE_*
	UI imgtype_of_res1;
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

	fmtutil_atari_decode_image(c, adata_mask);
	fmtutil_atari_decode_image(c, adata_fg);
	de_bitmap_apply_mask(adata_fg->img, adata_mask->img, 0);
	fi = de_finfo_create(c);
	fmtutil_atari_set_standard_density(c, adata_fg, fi);
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
	fmtutil_read_atari_palette(c, c->infile, pos+4, d->pal, 16, 16, 0);
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
	de_bitmap *fgimg = NULL;
	de_bitmap *maskimg = NULL;
	UI cvtflags = 0;
	i64 format_flag;
	i64 bgcol, fgcol;
	i64 w, h;
	i64 rowspan;
	i64 bitsstart;

	de_dbg(c, "icon #%d, at %d", (int)idx, (int)pos);
	de_dbg_indent(c, 1);

	format_flag = de_getu16be(pos+4);
	de_dbg(c, "format flag: 0x%04x", (unsigned int)format_flag);
	bgcol = de_getu16be(pos+6);
	fgcol = de_getu16be(pos+8);
	de_dbg(c, "bgcol: 0x%04x, fgcol: 0x%04x", (unsigned int)bgcol, (unsigned int)fgcol);

	// TODO: I don't know how to figure out what colors to use.
	if(fgcol==0 && bgcol!=0) {
		;
	}
	else {
		cvtflags |= DE_CVTF_WHITEISZERO;
	}

	w = 16;
	h = 16;
	rowspan = 4;
	fgimg = de_bitmap_create(c, w, h, 2);
	maskimg = de_bitmap_create(c, w, h, 1);

	bitsstart = pos + 10;

	de_convert_image_bilevel(c->infile, bitsstart, rowspan, maskimg, 0);
	de_convert_image_bilevel(c->infile, bitsstart+2, rowspan, fgimg, cvtflags);
	de_bitmap_apply_mask(fgimg, maskimg, 0);

	de_bitmap_write_to_file(fgimg, NULL, 0);
	de_bitmap_destroy(fgimg);
	de_bitmap_destroy(maskimg);
	de_dbg_indent(c, -1);
}

struct pictbank_params {
	u8 ok;
	UI num_planes;
	UI bits_per_pixel;
	i64 width_in_bytes;
	i64 height_in_lumps;
	i64 lines_per_lump;
	i64 pseudoheight;
	dbuf *unc_pixels;
	de_bitmap *img;
	de_color *pal;
};

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

static void render_stos_pp3(deark *c, struct pictbank_params *pb, i64 width_in_words)
{
	i64 planesize;
	i64 lump;

	planesize = pb->width_in_bytes * pb->pseudoheight;

	for(lump=0; lump<pb->height_in_lumps; lump++) {
		i64 col_idx;
		i64 lump_start_srcpos_in_plane;
		i64 lump_start_ypos;

		lump_start_srcpos_in_plane = pb->width_in_bytes * pb->lines_per_lump * lump;
		lump_start_ypos = pb->lines_per_lump * lump * 2;

		// col_idx=0 = the first 32 pixels of the even numbered rows
		// col_idx=width_in_words = the first 32 pixels of the odd numbered rows
		// (TODO: What happens if width_in_words is odd?)
		for(col_idx=0; col_idx<pb->width_in_bytes; col_idx++) {
			i64 col_start_srcpos_in_plane;
			i64 ypos_in_lump;
			UI rowparity;

			if(col_idx & 1) {
				continue; // We process 2 columns at a time
			}

			if(col_idx >= width_in_words) {
				rowparity = 1;
			}
			else {
				rowparity = 0;
			}

			col_start_srcpos_in_plane = lump_start_srcpos_in_plane + col_idx*pb->lines_per_lump;

			for(ypos_in_lump=0; ypos_in_lump<pb->lines_per_lump; ypos_in_lump++) {
				UI i;
				UI n;
				i64 xpos, ypos;

				ypos = lump_start_ypos + ypos_in_lump*2 + rowparity;

				if(rowparity) {
					xpos = (col_idx % width_in_words)*16;
				}
				else {
					xpos = col_idx*16;
				}

				// n=0: the first 8 pixels of every 32   plane 0 lump+0
				// n=1: the second 8 pixels of every 32  plane 0 lump+1
				// n=2: the third 8 pixels of every 32   plane 1 lump+0
				// n=3: the fourth 8 pixels of every 32  plane 1 lump+1
				for(n=0; n<4; n++) {
					u8 v;

					v = dbuf_getbyte(pb->unc_pixels, planesize*(n>>1) +
						col_start_srcpos_in_plane + pb->lines_per_lump*(n&1) + ypos_in_lump);

					for(i=0; i<8; i++) {
						UI palent;

						palent = (v>>(7-i)) & 1;
						de_bitmap_setpixel_rgb(pb->img, xpos, ypos, pb->pal[palent]);
						xpos++;
					}
				}
			}
		}
	}
}

static void render_stos_pp1(deark *c, struct pictbank_params *pb)
{
	i64 planesize;
	i64 lump;
	UI num_planes = 2;
	UI bits_per_pixel = 4;
	u8 xbuf[4];

	planesize = pb->width_in_bytes * pb->pseudoheight;

	for(lump=0; lump<pb->height_in_lumps; lump++) {
		i64 col_idx;
		i64 lump_start_srcpos_in_plane;
		i64 lump_start_ypos;
		i64 num_skipped_cols = 0;

		lump_start_srcpos_in_plane = pb->width_in_bytes * pb->lines_per_lump * lump;
		lump_start_ypos = pb->lines_per_lump * lump;

		for(col_idx=0; col_idx<pb->width_in_bytes; col_idx++) {
			i64 col_start_srcpos_in_plane;
			i64 ypos_in_lump;

			// Skip the last 2 of every group of 4 columns. They contain bits
			// associated with the first 2 columns.
			if((col_idx&2)!=0) {
				num_skipped_cols++;
				continue;
			}

			col_start_srcpos_in_plane = lump_start_srcpos_in_plane +
				pb->lines_per_lump*col_idx;

			for(ypos_in_lump=0; ypos_in_lump<pb->lines_per_lump; ypos_in_lump++) {
				UI i;
				UI pn;
				i64 xpos, ypos;

				ypos = lump_start_ypos + ypos_in_lump;

				for(pn=0; pn<num_planes; pn++) {
					xbuf[pn] = dbuf_getbyte(pb->unc_pixels, planesize*pn +
						col_start_srcpos_in_plane + ypos_in_lump);
					xbuf[pn+2] = dbuf_getbyte(pb->unc_pixels, planesize*pn +
						col_start_srcpos_in_plane + 2*pb->lines_per_lump + ypos_in_lump);
				}

				for(i=0; i<8; i++) {
					UI palent;

					palent = 0;
					for(pn=0; pn<bits_per_pixel; pn++) {
						if(xbuf[pn] & (1<<(7-i))) {
							palent |= (1<<pn);
						}
					}

					xpos = (col_idx-num_skipped_cols)*8 + i;
					de_bitmap_setpixel_rgb(pb->img, xpos, ypos, pb->pal[palent]);
				}
			}
		}
	}
}

static void render_stos_med4plane(deark *c, struct pictbank_params *pb)
{
	i64 planesize;
	i64 lump;
	UI num_planes = 4;
	UI bits_per_pixel = 2;
	u8 xbuf[4];

	//width_in_bytes = pb->width_in_words*2;
	planesize = pb->width_in_bytes * pb->pseudoheight;

	for(lump=0; lump<pb->height_in_lumps; lump++) {
		i64 col_idx;
		i64 lump_start_srcpos_in_plane;
		i64 lump_start_ypos;

		lump_start_srcpos_in_plane = pb->width_in_bytes * pb->lines_per_lump * lump;
		lump_start_ypos = pb->lines_per_lump * lump;

		for(col_idx=0; col_idx<pb->width_in_bytes; col_idx++) {
			i64 col_start_srcpos_in_plane;
			i64 ypos_in_lump;

			// Each column that we process sets 16 pixels:
			// 8 pixels are set, then 8 pixels skipped, then 8 pixels set.

			col_start_srcpos_in_plane = lump_start_srcpos_in_plane +
				pb->lines_per_lump*col_idx;

			for(ypos_in_lump=0; ypos_in_lump<pb->lines_per_lump; ypos_in_lump++) {
				UI i;
				UI pn;
				i64 xpos1, ypos;

				ypos = lump_start_ypos + ypos_in_lump;

				// xbuf[0..1] are for the first set of 8 pixels.
				// xbuf[2..3] are for the second set.
				for(pn=0; pn<num_planes; pn++) {
					xbuf[pn] = dbuf_getbyte(pb->unc_pixels, planesize*pn +
						col_start_srcpos_in_plane + ypos_in_lump);
				}

				xpos1 = col_idx*16;
				if(col_idx%2) xpos1 -= 8;

				for(i=0; i<8; i++) {
					i64 xpos;
					UI palent;
					UI pixset;

					for(pixset=0; pixset<2; pixset++) {
						palent = 0;
						for(pn=0; pn<bits_per_pixel; pn++) {
							if(xbuf[pixset*2+pn] & (1<<(7-i))) {
								palent |= (1<<pn);
							}
						}
						xpos = xpos1 + pixset*16 + i;
						de_bitmap_setpixel_rgb(pb->img, xpos, ypos, pb->pal[palent]);
					}
				}
			}
		}
	}
}

// TODO: Consolidate this with the similar function in abk.c.
static void render_stos_pictbank_std(deark *c, struct pictbank_params *pb)
{
	i64 planesize;
	i64 lump;
	u8 xbuf[8];

	if((size_t)pb->num_planes > sizeof(xbuf)) goto done;
	if(pb->bits_per_pixel != pb->num_planes) goto done;
	de_zeromem(xbuf, sizeof(xbuf));
	planesize = pb->width_in_bytes * pb->pseudoheight;

	for(lump=0; lump<pb->height_in_lumps; lump++) {
		i64 col_idx;
		i64 lump_start_srcpos_in_plane;
		i64 lump_start_ypos;

		lump_start_srcpos_in_plane = pb->width_in_bytes * pb->lines_per_lump * lump;
		lump_start_ypos = pb->lines_per_lump * lump;

		for(col_idx=0; col_idx<pb->width_in_bytes; col_idx++) {
			i64 col_start_srcpos_in_plane;
			i64 ypos_in_lump;

			col_start_srcpos_in_plane = lump_start_srcpos_in_plane +
				pb->lines_per_lump*col_idx;

			for(ypos_in_lump=0; ypos_in_lump<pb->lines_per_lump; ypos_in_lump++) {
				UI i;
				UI pn;
				i64 xpos, ypos;

				ypos = lump_start_ypos + ypos_in_lump;

				for(pn=0; pn<pb->num_planes; pn++) {
					xbuf[pn] = dbuf_getbyte(pb->unc_pixels, planesize*pn +
						col_start_srcpos_in_plane + ypos_in_lump);
				}

				for(i=0; i<8; i++) {
					UI palent;

					palent = 0;
					for(pn=0; pn<pb->bits_per_pixel; pn++) {
						if(xbuf[pn] & (1<<(7-i))) {
							palent |= (1<<pn);
						}
					}

					xpos = col_idx*8 + i;
					de_bitmap_setpixel_rgb(pb->img, xpos, ypos, pb->pal[palent]);
				}
			}
		}
	}

	pb->ok = 1;

done:
	;
}

static void render_stos_pictbank1(deark *c, lctx *d, struct pkpic_ctx *pp,
	dbuf *unc_pixels, de_bitmap *img, UI num_planes)
{
	struct pictbank_params *pb;

	pb = de_malloc(c, sizeof(struct pictbank_params));
	pb->num_planes = num_planes;
	pb->bits_per_pixel = pb->num_planes;
	pb->width_in_bytes = pp->width_in_words * 2;
	pb->height_in_lumps = pp->height_in_lumps;
	pb->lines_per_lump = pp->lines_per_lump;
	pb->pseudoheight = pp->pseudoheight;
	pb->unc_pixels = unc_pixels;
	pb->img = img;
	pb->pal = d->pal;

	if(pp->imgtype==PKPIC_IMGTYPE_PP1) {
		render_stos_pp1(c, pb);
	}
	else if(pp->imgtype==PKPIC_IMGTYPE_PP3) {
		render_stos_pp3(c, pb, pp->width_in_words);
	}
	else if(pp->imgtype==PKPIC_IMGTYPE_M4P) {
		render_stos_med4plane(c, pb);
	}
	else {
		render_stos_pictbank_std(c, pb);
	}

	de_free(c, pb);
}

static void do_pkscreen_bank(deark *c, lctx *d, i64 pos1)
{
	struct pkpic_ctx *pp = NULL;
	dbuf *unc_pixels = NULL;
	de_bitmap *img = NULL;
	struct atari_img_decode_data *adata = NULL;
	de_finfo *fi = NULL;
	const char *tname = NULL;
	i64 pos;
	UI num_planes;
	UI bits_per_pixel;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	pp = de_malloc(c, sizeof(struct pkpic_ctx));
	de_zeromem(d->pal, sizeof(d->pal));

	pos = pos1+4;
	pp->res_code = (UI)de_getu16be_p(&pos);
	de_dbg(c, "res: %u", pp->res_code);

	switch(pp->res_code) {
	case 0:
		if(d->imgtype_of_res0==PKPIC_IMGTYPE_UNKNOWN) {
			pp->imgtype = PKPIC_IMGTYPE_LOW;
		}
		else {
			pp->imgtype = d->imgtype_of_res0;
		}
		break;
	case 1:
		if(d->imgtype_of_res1==PKPIC_IMGTYPE_UNKNOWN) {
			const char *tmps;

			if(d->is_container_fmt) {
				pp->imgtype = PKPIC_IMGTYPE_MED;
				tmps = "l|h";
			}
			else {
				// Unfortunately, a file with res=1 (that couldn't be identified by
				// its extension) seems to be more likely to be the oddball PP1
				// format than the nice standard STOS medium-resolution format.
				pp->imgtype = PKPIC_IMGTYPE_PP1;
				tmps = "m|h";
			}
			de_warn(c, "Ambiguous image. If it looks wrong, try \"-opt stos:res1=<%s>\".", tmps);
		}
		else {
			pp->imgtype = d->imgtype_of_res1;
		}
		break;
	case 2: pp->imgtype = PKPIC_IMGTYPE_HIGH; break;
	default: pp->imgtype = PKPIC_IMGTYPE_UNKNOWN; break;
	}

	switch(pp->imgtype) {
	case PKPIC_IMGTYPE_LOW:
		num_planes = 4;
		bits_per_pixel = 4;
		tname = "4-plane low res";
		break;
	case PKPIC_IMGTYPE_M4P:
		num_planes = 4;
		bits_per_pixel = 2;
		tname = "DAJ 4-plane med res";
		break;
	case PKPIC_IMGTYPE_MED:
		num_planes = 2;
		bits_per_pixel = 2;
		tname = "2-plane med res";
		break;
	case PKPIC_IMGTYPE_HIGH:
		num_planes = 1;
		bits_per_pixel = 1;
		tname = "1-plane high res";
		break;
	case PKPIC_IMGTYPE_PP1:
		num_planes = 2;
		bits_per_pixel = 4;
		tname = "PP1 2-plane low res";
		break;
	case PKPIC_IMGTYPE_PP3:
		num_planes = 2;
		bits_per_pixel = 1;
		tname = "PP3 2-plane high res";
		break;
	default:
		de_err(c, "Unsupported picture resolution: %u", pp->res_code);
		goto done;
	}
	if(tname) {
		de_dbg(c, "interpreted image type: %s", tname);
	}

	pos += 4;
	pp->width_in_words = de_getu16be_p(&pos);
	pp->pseudowidth = pp->width_in_words * 16;
	if(pp->imgtype==PKPIC_IMGTYPE_PP1) {
		pp->w = pp->width_in_words * 8;
	}
	else if(pp->imgtype==PKPIC_IMGTYPE_M4P) {
		pp->w = pp->width_in_words * 32;
	}
	else {
		pp->w = pp->pseudowidth;
	}
	de_dbg(c, "width in words: %"I64_FMT, pp->width_in_words);
	pp->height_in_lumps = de_getu16be_p(&pos);
	de_dbg(c, "height in lumps: %"I64_FMT, pp->height_in_lumps);
	pos += 2; // unknown
	pp->lines_per_lump = de_getu16be_p(&pos);
	de_dbg(c, "lines per lump: %"I64_FMT, pp->lines_per_lump);
	pp->pseudoheight = pp->height_in_lumps * pp->lines_per_lump;
	if(pp->imgtype==PKPIC_IMGTYPE_PP3) {
		pp->h = pp->pseudoheight * 2;
	}
	else {
		pp->h = pp->pseudoheight;
	}
	de_dbg_dimensions(c, pp->w, pp->h);
	pos += 2; // flags
	pp->picdata_rel = 70;
	pp->rledata_rel = de_getu32be_p(&pos);
	pp->pointdata_rel = de_getu32be_p(&pos);
	pp->picdata_abs = pos1 + pp->picdata_rel;
	pp->rledata_abs = pos1 + pp->rledata_rel;
	pp->pointdata_abs = pos1 + pp->pointdata_rel;
	de_dbg(c, "picdata: %"I64_FMT, pp->picdata_abs);
	de_dbg(c, "rledata: %"I64_FMT, pp->rledata_abs);
	de_dbg(c, "pointdata: %"I64_FMT, pp->pointdata_abs);

	pos = pos1+38;
	de_dbg(c, "palette at %"I64_FMT, pos);
	de_dbg_indent(c, 1);
	fmtutil_read_atari_palette(c, c->infile, pos, d->pal, 16, 16, 0);
	de_dbg_indent(c, -1);

	if(bits_per_pixel==1) {
		if((d->pal[0] & 0xffffff)==0) {
			d->pal[0] = DE_STOCKCOLOR_BLACK;
			d->pal[1] = DE_STOCKCOLOR_WHITE;
		}
		else {
			d->pal[0] = DE_STOCKCOLOR_WHITE;
			d->pal[1] = DE_STOCKCOLOR_BLACK;
		}
	}

	pp->unc_image_size = pp->width_in_words*2 * (i64)num_planes * pp->h;

	unc_pixels = dbuf_create_membuf(c, 0, 0);

	fmtutil_decompress_stos_pictbank(c, c->infile, pp->picdata_abs, pp->rledata_abs,
		pp->pointdata_abs, unc_pixels, pp->unc_image_size);

	img = de_bitmap_create(c, pp->w, pp->h, ((bits_per_pixel==1)?1:3));
	render_stos_pictbank1(c, d, pp, unc_pixels, img, num_planes);

	fi = de_finfo_create(c);
	adata = de_malloc(c, sizeof(struct atari_img_decode_data));
	adata->bpp = (i64)bits_per_pixel;
	fmtutil_atari_set_standard_density(c, adata, fi);
	de_bitmap_write_to_file_finfo(img, fi, 0);

done:
	de_bitmap_destroy(img);
	dbuf_close(unc_pixels);
	if(pp) {
		de_free(c, pp);
	}
	de_free(c, adata);
	de_finfo_destroy(c, fi);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_mbk_data_bank(deark *c, lctx *d, i64 pos)
{
	const char *bn = "?";

	de_dbg(c, "STOS data bank at %d", (int)pos);
	de_dbg_indent(c, 1);
	d->data_bank_id = (u32)de_getu32be(pos);

	switch(d->data_bank_id) {
	case BANKID_PKSCREEN: bn = "packed screen"; break;
	case 0x13490157U: bn = "music bank"; break;
	case 0x28091960U: bn = "icon bank"; break;
	case BANKID_SPRITE: bn = "sprite bank"; break;
	case 0x4d414553U: bn = "Maestro!"; break;
	}

	de_dbg(c, "data bank id: 0x%08x (%s)", (unsigned int)d->data_bank_id, bn);

	switch(d->data_bank_id) {
	case BANKID_SPRITE:
		do_sprite_bank(c, d, pos);
		break;
	case 0x28091960U:
		do_icon_bank(c, d, pos);
		break;
	case BANKID_PKSCREEN:
		do_pkscreen_bank(c, d, pos);
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

static void run_mbk_mbs_internal(deark *c, de_module_params *mparams, UI mode)
{
	lctx *d = NULL;
	u32 id;
	const char *s;
	char opt_res0_c = '\0';
	char opt_res1_c = '\0';
	u8 buf[10];

	d = de_malloc(c, sizeof(lctx));

	d->imgtype_of_res1 = PKPIC_IMGTYPE_UNKNOWN;
	d->imgtype_of_res0 = PKPIC_IMGTYPE_UNKNOWN;

	if(mode==1) { // .pp1 extension
		d->imgtype_of_res1 = PKPIC_IMGTYPE_PP1;
	}
	else if(mode==2) {
		d->imgtype_of_res1 = PKPIC_IMGTYPE_MED;
	}
	else if(mode==3) {
		d->imgtype_of_res1 = PKPIC_IMGTYPE_PP3;
	}
	else if(mode==4) { // .daj extension
		d->imgtype_of_res0 = PKPIC_IMGTYPE_M4P;
		d->imgtype_of_res1 = PKPIC_IMGTYPE_MED;
	}

	s = de_get_ext_option(c, "stos:res0");
	if(s) opt_res0_c = s[0];
	s = de_get_ext_option(c, "stos:res1");
	if(s) opt_res1_c = s[0];

	if(opt_res1_c=='l') {
		d->imgtype_of_res1 = PKPIC_IMGTYPE_PP1;
	}
	else if(opt_res1_c=='m') {
		d->imgtype_of_res1 = PKPIC_IMGTYPE_MED;
	}
	else if(opt_res1_c=='h') {
		d->imgtype_of_res1 = PKPIC_IMGTYPE_PP3;
	}

	if(opt_res0_c=='l') {
		d->imgtype_of_res0 = PKPIC_IMGTYPE_LOW;
	}
	else if(opt_res0_c=='m') {
		d->imgtype_of_res0 = PKPIC_IMGTYPE_M4P;
	}

	de_read(buf, 0, sizeof(buf));
	if(!de_memcmp(buf, g_lion_sig, 10)) {
		d->is_container_fmt = 1;
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

		if(id==BANKID_SPRITE) {
			de_declare_fmt(c, "STOS Sprite Bank");
			do_sprite_bank(c, d, 0);
		}
		else if(id==BANKID_PKSCREEN) {
			de_declare_fmt(c, "STOS Packed Screen / Picture Packer");
			do_pkscreen_bank(c, d, 0);
		}
		else {
			de_err(c, "Not a (supported) STOS/MBK format");
		}
	}

	de_free(c, d);
}

static void de_run_mbk_mbs(deark *c, de_module_params *mparams)
{
	run_mbk_mbs_internal(c, mparams, 0);
}

// Detects raw packed screen, and MBK containing packed screen.
// Returns the resolution in *res.
static int is_stos_packedscreen(deark *c, UI *res)
{
	u8 buf[24];
	u8 is_mbk = 0;
	UI id = 0;
	UI field14;
	UI field18;
	i64 bpos = 0;

	*res = 0;
	de_read(buf, 0, sizeof(buf));

	if(!de_memcmp(buf, g_lion_sig, 10)) is_mbk = 1;
	if(is_mbk) {
		if((UI)de_getu32be_direct(&buf[10]) == 0) return 0; // screen out MBS
		if(buf[14] != 0x81) return 0; // must be type 'data'
		bpos = 18;
	}

	id = (UI)de_getu32be_direct(&buf[bpos]);
	if(id!=BANKID_PKSCREEN) return 0;
	*res = (UI)de_getu16be_direct(&buf[bpos+4]);
	if(*res > 2) return 0;

	field14 = (UI)de_getu16be_direct(&buf[bpos+14]);
	if(field14>=1 && field14<=6) {
		// It's likely that this is the AMOS format, not the STOS format.
		field18 = (UI)de_getu16be_direct(&buf[bpos+18]);
		// Expecting STOS flags to be small
		if(field18>=8) return 0;
	}
	return 1;
}

// Note: Returned values must be kept consistent with other stos modules.
static int de_identify_mbk(deark *c)
{
	u8 buf[10];
	UI id;

	de_read(buf, 0, sizeof(buf));
	if(!de_memcmp(buf, g_lion_sig, 10))
		return 99;
	id = (UI)de_getu32be_direct(buf);
	if(id==BANKID_SPRITE) {
		return 100;
	}
	else if(id==BANKID_PKSCREEN) {
		int is_pkscr;
		UI res;

		is_pkscr = is_stos_packedscreen(c, &res);
		if(is_pkscr) {
			return 99;
		}
	}
	return 0;
}

static void de_help_mbk(deark *c)
{
	fmtutil_atari_help_palbits(c);
	de_msg(c, "-opt stos:res0=<l|m> : Assume res 0 pics are low/med res");
	de_msg(c, "-opt stos:res1=<l|m|h> : Assume res 1 pics are low/med/high res");
}

void de_module_mbk(deark *c, struct deark_module_info *mi)
{
	mi->id = "stos";
	mi->desc = "STOS Memory Bank (.MBK)";
	mi->run_fn = de_run_mbk_mbs;
	mi->identify_fn = de_identify_mbk;
	mi->help_fn = de_help_mbk;
	mi->id_alias[0] = "mbk";
}

// Note: Returned values must be kept consistent with other stos modules.
static int de_identify_stos_pp1(deark *c)
{
	int has_ext;
	int is_pkscr;
	UI res;

	has_ext = de_input_file_has_ext(c, "pp1");
	if(!has_ext) return 0;
	is_pkscr = is_stos_packedscreen(c, &res);
	if(is_pkscr && res==1) return 100;
	return 0;
}

static void de_run_stos_pp1(deark *c, de_module_params *mparams)
{
	run_mbk_mbs_internal(c, mparams, 1);
}

void de_module_stos_pp1(deark *c, struct deark_module_info *mi)
{
	mi->id = "stos_pp1";
	mi->desc = "Picture Packer low res";
	mi->run_fn = de_run_stos_pp1;
	mi->identify_fn = de_identify_stos_pp1;
	mi->help_fn = de_help_mbk;
}

static void de_run_stos_pp2(deark *c, de_module_params *mparams)
{
	run_mbk_mbs_internal(c, mparams, 2);
}

// Note: Returned values must be kept consistent with other stos modules.
static int de_identify_stos_pp2(deark *c)
{
	int has_ext;
	int is_pkscr;
	UI res;

	has_ext = de_input_file_has_ext(c, "pp2");
	if(!has_ext) return 0;
	is_pkscr = is_stos_packedscreen(c, &res);
	if(is_pkscr && res==1) return 100;
	return 0;
}

void de_module_stos_pp2(deark *c, struct deark_module_info *mi)
{
	mi->id = "stos_pp2";
	mi->desc = "Picture Packer med res";
	mi->run_fn = de_run_stos_pp2;
	mi->identify_fn = de_identify_stos_pp2;
	mi->help_fn = de_help_mbk;
}

static void de_run_stos_pp3(deark *c, de_module_params *mparams)
{
	run_mbk_mbs_internal(c, mparams, 3);
}

// Note: Returned values must be kept consistent with other stos modules.
static int de_identify_stos_pp3(deark *c)
{
	int has_ext;
	int is_pkscr;
	UI res;

	has_ext = de_input_file_has_ext(c, "pp3");
	if(!has_ext) return 0;
	is_pkscr = is_stos_packedscreen(c, &res);
	if(is_pkscr && res==1) return 100;
	return 0;
}

void de_module_stos_pp3(deark *c, struct deark_module_info *mi)
{
	mi->id = "stos_pp3";
	mi->desc = "Picture Packer high res";
	mi->run_fn = de_run_stos_pp3;
	mi->identify_fn = de_identify_stos_pp3;
	mi->help_fn = de_help_mbk;
}

static void de_run_stos_daj(deark *c, de_module_params *mparams)
{
	run_mbk_mbs_internal(c, mparams, 4);
}

// Note: Returned values must be kept consistent with other stos modules.
static int de_identify_stos_daj(deark *c)
{
	int has_ext;
	int is_pkscr;
	UI res;

	has_ext = de_input_file_has_ext(c, "daj");
	if(!has_ext) return 0;
	is_pkscr = is_stos_packedscreen(c, &res);
	if(is_pkscr && (res==0 || res==1)) return 100;
	return 0;
}

// .DAJ, a 4-plane medium res format, seems to be used only by a presentation-like
// viewer used by the ST+ (ST Plus) Atari diskmagazine.
void de_module_stos_daj(deark *c, struct deark_module_info *mi)
{
	mi->id = "stos_daj";
	mi->desc = "Picture Packer DAJ";
	mi->run_fn = de_run_stos_daj;
	mi->identify_fn = de_identify_stos_daj;
	mi->help_fn = de_help_mbk;
}
