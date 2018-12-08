// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Award BIOS logo formats

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_awbm);

typedef struct localctx_struct {
	i64 w, h;
	int rgb_order;
} lctx;

#define EPA_CH 14 // "character" height (width must be 8)

static int do_v1_image(deark *c, i64 pos,
	i64 w_blocks, i64 h_blocks, int special, unsigned int createflags)
{
	de_bitmap *img = NULL;
	i64 w, h;
	i64 i, j, i2, j2;
	i64 colors_start=0, bitmap_start;
	u8 b;
	u32 clr1, clr2;
	int retval = 0;

	w = 8 * w_blocks;
	h = EPA_CH * h_blocks;
	if(!de_good_image_dimensions(c, w, h)) goto done;
	img = de_bitmap_create(c, w, h, special?4:3);

	if(special) {
		// The first block is not stored, and is assumed to be blank.
		// To compensate, pretend the image starts 1 block before it does.
		// (There's special code later to make the first block blank.)
		bitmap_start = pos - EPA_CH;
	}
	else {
		colors_start = pos;
		bitmap_start = colors_start + w_blocks*h_blocks;
	}

	// Read the bitmap, "character by character"
	for(j=0; j<h_blocks; j++) {
		for(i=0; i<w_blocks; i++) {
			if(special) {
				if(j==0 && i==0) {
					// No data (transparent)
					clr1 = DE_STOCKCOLOR_TRANSPARENT;
					clr2 = DE_STOCKCOLOR_TRANSPARENT;
				}
				else {
					// Blue on black
					clr1 = DE_MAKE_RGB(0x00,0x00,0xff);
					clr2 = DE_STOCKCOLOR_BLACK;
				}
			}
			else {
				// Read the color attributes for this block of pixel
				b = de_getbyte(colors_start + j*w_blocks + i);
				clr1 = de_palette_pc16((int)(b&0x0f));
				clr2 = de_palette_pc16((int)((b&0xf0)>>4));
			}

			// Read each individual pixel
			for(j2=0; j2<EPA_CH; j2++) {
				for(i2=0; i2<8; i2++) {
					if(special && j==0 && i==0) {
						b = 0;
					}
					else {
						b = de_get_bits_symbol(c->infile, 1,
							bitmap_start + j*w_blocks*EPA_CH + i*EPA_CH + j2, i2);
					}
					de_bitmap_setpixel_rgba(img, i*8+i2, j*EPA_CH+j2, b?clr1:clr2);
				}
			}
		}
	}
	de_bitmap_write_to_file(img, NULL, createflags);
	retval = 1;
done:
	de_bitmap_destroy(img);
	return retval;
}

static void do_v1(deark *c, lctx *d)
{
	i64 w_blocks, h_blocks;
	i64 after_bitmap;

	de_declare_fmt(c, "Award BIOS logo v1");

	w_blocks = (i64)de_getbyte(0);
	h_blocks = (i64)de_getbyte(1);
	if(!do_v1_image(c, 2, w_blocks, h_blocks, 0, 0)) goto done;

	after_bitmap = 2 + w_blocks*h_blocks + h_blocks*EPA_CH*w_blocks;
	if(c->infile->len >= after_bitmap+70) {
		// The file usually contains a second image: a small Award logo.
		do_v1_image(c, after_bitmap, 3, 2, 1, DE_CREATEFLAG_IS_AUX);
	}
done:
	;
}

static int detect_palette_at(deark *c, lctx *d, i64 pos, i64 ncolors)
{
	if(pos + 4 + 3*ncolors > c->infile->len) return 0;
	if(!dbuf_memcmp(c->infile, pos, "RGB ", 4)) return 1;
	return 0;
}


static void do_v2(deark *c, lctx *d)
{
	de_bitmap *img = NULL;
	i64 rowspan1;
	i64 rowspan;
	i64 bitmap_start;
	i64 bitmap_size;
	i64 palette_start;
	i64 i, j;
	i64 k;
	u8 cr, cg, cb;
	u8 b;
	u8 b1;
	const char *s;
	i64 ncolors = 0; // 16 or 256
	u32 pal[256];

	de_zeromem(pal, sizeof(pal));
	d->w = de_getu16le(4);
	d->h = de_getu16le(6);
	de_dbg_dimensions(c, d->w, d->h);
	if(!de_good_image_dimensions(c, d->w, d->h)) goto done;

	bitmap_start = 8;
	rowspan1 = (d->w+7)/8;

	rowspan = d->w; // Start by guessing 8bpp
	bitmap_size = rowspan * d->h;

	if(detect_palette_at(c, d, bitmap_start+bitmap_size, 256)) {
		ncolors=256;
		de_declare_fmt(c, "Award BIOS logo v2 8-bit");
	}
	else {
		// Doesn't seem to be an 8pp image. Try 4bpp.
		rowspan = rowspan1 * 4;
		bitmap_size = rowspan * d->h;
		if(detect_palette_at(c, d, bitmap_start+bitmap_size, 16)) {
			ncolors=16;
			de_declare_fmt(c, "Award BIOS logo v2 4-bit");
		}
	}

	if(!ncolors) {
		de_err(c, "Can't detect image format");
		goto done;
	}

	// Default to BGR for 16-color images, RGB for 256-color.
	if(ncolors==16)
		d->rgb_order = 0;
	else
		d->rgb_order = 1;

	s = de_get_ext_option(c, "awbm:rgb");
	if(s) d->rgb_order = de_atoi(s);

	palette_start = bitmap_start+bitmap_size+4;

	// Read the palette
	for(i=0; i<ncolors; i++) {
		cr = de_scale_63_to_255(de_getbyte(palette_start+i*3+0));
		cg = de_scale_63_to_255(de_getbyte(palette_start+i*3+1));
		cb = de_scale_63_to_255(de_getbyte(palette_start+i*3+2));
		if(d->rgb_order)
			pal[i] = DE_MAKE_RGB(cr, cg, cb);
		else
			pal[i] = DE_MAKE_RGB(cb, cg, cr);
	}

	img = de_bitmap_create(c, d->w, d->h, 3);
	for(j=0; j<d->h; j++) {
		for(i=0; i<d->w; i++) {
			if(ncolors==16) {
				b = 0;
				for(k=0; k<4; k++) {
					b1 = de_get_bits_symbol(c->infile, 1, bitmap_start + j*rowspan + k*rowspan1, i);
					b |= b1<<k;
				}
			}
			else {
				b = de_getbyte(bitmap_start + j*rowspan + i);
			}
			de_bitmap_setpixel_rgb(img, i, j, pal[(unsigned int)b]);
		}
	}

	de_bitmap_write_to_file(img, NULL, 0);
done:
	de_bitmap_destroy(img);
}

static void de_run_awbm(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	if(!dbuf_memcmp(c->infile, 0, "AWBM", 4)) {
		do_v2(c, d);
	}
	else {
		do_v1(c, d);
	}

	de_free(c, d);
}

static int de_identify_awbm(deark *c)
{
	u8 buf[4];
	i64 nblocks;
	int epa_ext;

	de_read(buf, 0, 4);
	if(!de_memcmp(buf, "AWBM", 4)) return 100;

	nblocks = (i64)buf[0] * (i64)buf[1];
	if(nblocks<1 || nblocks>256) return 0;
	if(c->infile->len == 2 + nblocks*15 + 70) {
		epa_ext = de_input_file_has_ext(c, "epa");
		if(epa_ext) return 100;
		return 20;
	}
	return 0;
}

static void de_help_awbm(deark *c)
{
	de_msg(c, "-opt awbm:rgb=0 : Assume BGR sample order");
	de_msg(c, "-opt awbm:rgb=1 : Assume RGB sample order");
}

void de_module_awbm(deark *c, struct deark_module_info *mi)
{
	mi->id = "awbm";
	mi->desc = "Award BIOS logo";
	mi->run_fn = de_run_awbm;
	mi->identify_fn = de_identify_awbm;
	mi->help_fn = de_help_awbm;
}
